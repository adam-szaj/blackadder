"""
Binary matching via assembly fingerprints.

Enables matching process binaries to database binaries even when
MD5 differs due to version mismatches or custom builds.
Includes comprehensive error handling and validation (Phase 2 hardening).
"""

import logging

from sqlmodel import select
from sqlalchemy.ext.asyncio import AsyncSession

from blackadder.models import Binary, FunctionFingerprint
from blackadder.exceptions import (
    ValidationError,
    DatabaseQueryError,
)

logger = logging.getLogger("blackadder.matcher")


class BinaryMatcher:
    """Match process binary to available binaries via fingerprints."""

    @staticmethod
    async def find_matches(
        target_fingerprints: dict[str, str],
        available_binaries: list[Binary],
        session: AsyncSession,
        threshold: float = 0.7,
    ) -> list[tuple[Binary, float, str]]:
        """
        Find best binary matches for target.

        Strategy:
        1. For each available binary, load its fingerprints from DB
        2. Compare target fingerprints to each binary's fingerprints
        3. Score: (matching_functions / total_functions)
        4. Return binaries with score >= threshold, sorted by score

        Args:
            target_fingerprints: {func_name: content_hash} from process binary
            available_binaries: List of Binary models from rootfs DB
            session: AsyncSession for database queries
            threshold: Min match score to accept (0.0-1.0)

        Returns:
            List of (Binary, match_score, match_method) tuples, sorted descending by score

        Raises:
            ValidationError: If inputs are invalid
            DatabaseQueryError: If database queries fail
        """
        try:
            # Input validation (Phase 2 hardening)
            if not isinstance(target_fingerprints, dict):
                logger.error(f"Invalid target_fingerprints type: {type(target_fingerprints)}")
                raise ValidationError(f"target_fingerprints must be dict")

            if not isinstance(available_binaries, list):
                logger.error(f"Invalid available_binaries type: {type(available_binaries)}")
                raise ValidationError(f"available_binaries must be list")

            if not isinstance(threshold, (int, float)):
                logger.error(f"Invalid threshold type: {type(threshold)}")
                raise ValidationError(f"threshold must be float")

            if not (0.0 <= threshold <= 1.0):
                logger.warning(f"Threshold out of range: {threshold} (should be 0.0-1.0)")
                raise ValidationError(f"threshold must be between 0.0 and 1.0, got {threshold}")

            if not session:
                logger.error("AsyncSession is None")
                raise ValidationError(f"session cannot be None")

            logger.debug(
                f"Matching {len(target_fingerprints)} target fingerprints "
                f"against {len(available_binaries)} binaries (threshold={threshold})"
            )

            matches = []

            for binary in available_binaries:
                if not binary or not binary.id:
                    logger.warning(f"Invalid binary in list: {binary}")
                    continue

                try:
                    # Load fingerprints for this binary
                    candidate_fps = await BinaryMatcher._load_fingerprints(session, binary.id)

                    if not candidate_fps:
                        # No fingerprints available, skip
                        continue

                    # Score the match
                    score = BinaryMatcher.score_match(target_fingerprints, candidate_fps)

                    if score >= threshold:
                        matches.append((binary, score, "hash"))
                        logger.debug(f"Match found: {binary.name} (score={score:.3f})")

                except Exception as e:
                    logger.warning(f"Failed to match binary {binary.id}: {e}")
                    continue

            # Sort by score descending
            matches.sort(key=lambda x: x[1], reverse=True)

            logger.debug(f"Found {len(matches)} matches above threshold")
            return matches

        except (ValidationError, DatabaseQueryError):
            raise
        except Exception as e:
            logger.error(f"Unexpected error finding matches: {e}")
            raise DatabaseQueryError(f"Binary matching failed: {e}")

    @staticmethod
    async def _load_fingerprints(
        session: AsyncSession, binary_id: int
    ) -> dict[str, str]:
        """
        Load fingerprints for a binary from database.

        Args:
            session: AsyncSession
            binary_id: Binary ID

        Returns:
            {func_name: content_hash} or {} if none found

        Raises:
            ValidationError: If binary_id is invalid
            DatabaseQueryError: If query fails
        """
        try:
            # Input validation (Phase 2 hardening)
            if not isinstance(binary_id, int):
                logger.warning(f"Invalid binary_id type: {type(binary_id)}")
                raise ValidationError(f"binary_id must be int")

            if binary_id <= 0:
                logger.warning(f"Invalid binary_id: {binary_id} (must be positive)")
                raise ValidationError(f"binary_id must be positive")

            logger.debug(f"Loading fingerprints for binary {binary_id}")

            statement = select(FunctionFingerprint).where(
                FunctionFingerprint.binary_id == binary_id
            )
            result = await session.exec(statement)
            fingerprints = result.all()

            fp_dict = {fp.func_name: fp.content_hash for fp in fingerprints}
            logger.debug(f"Loaded {len(fp_dict)} fingerprints for binary {binary_id}")
            return fp_dict

        except ValidationError:
            raise
        except Exception as e:
            logger.error(f"Error loading fingerprints for binary {binary_id}: {e}")
            raise DatabaseQueryError(f"Fingerprint load failed: {e}")

    @staticmethod
    def score_match(
        target_fps: dict[str, str],
        candidate_fps: dict[str, str],
    ) -> float:
        """
        Compute similarity score between fingerprint sets.

        Score = (matching functions) / (max(target, candidate) functions)

        Handles:
        - Stripped binaries (function names may be missing)
        - Minor code changes (some functions differ, most match)
        - Function reordering (doesn't affect score)

        Args:
            target_fps: {func_name: content_hash} from process binary
            candidate_fps: {func_name: content_hash} from database binary

        Returns:
            Score 0.0-1.0 where 1.0 = identical, 0.0 = no matches

        Raises:
            ValidationError: If inputs are invalid
        """
        try:
            # Input validation (Phase 2 hardening)
            if not isinstance(target_fps, dict):
                logger.warning(f"Invalid target_fps type: {type(target_fps)}")
                raise ValidationError(f"target_fps must be dict")

            if not isinstance(candidate_fps, dict):
                logger.warning(f"Invalid candidate_fps type: {type(candidate_fps)}")
                raise ValidationError(f"candidate_fps must be dict")

            # Validate dict contents
            for name, hash_val in target_fps.items():
                if not isinstance(name, str) or not isinstance(hash_val, str):
                    logger.warning(f"Invalid target fingerprint entry: {name}={hash_val}")
                    raise ValidationError(f"Fingerprints must map str→str")

            for name, hash_val in candidate_fps.items():
                if not isinstance(name, str) or not isinstance(hash_val, str):
                    logger.warning(f"Invalid candidate fingerprint entry: {name}={hash_val}")
                    raise ValidationError(f"Fingerprints must map str→str")

            if not target_fps or not candidate_fps:
                logger.debug("Empty fingerprint set(s)")
                return 0.0

            # Count matching functions (name + hash both match)
            matching = 0
            for func_name, target_hash in target_fps.items():
                if func_name in candidate_fps:
                    if candidate_fps[func_name] == target_hash:
                        matching += 1

            # Score: matching / max(len(target), len(candidate))
            # This handles cases where one set is a subset of the other
            max_count = max(len(target_fps), len(candidate_fps))

            if max_count == 0:
                logger.debug("No fingerprints to score")
                return 0.0

            score = matching / max_count
            final_score = min(score, 1.0)  # Ensure 0.0-1.0 range

            logger.debug(f"Scored match: {matching}/{max_count} = {final_score:.3f}")
            return final_score

        except ValidationError:
            raise
        except Exception as e:
            logger.error(f"Error scoring match: {e}")
            raise ValidationError(f"Match scoring failed: {e}")

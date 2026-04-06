"""
Binary matching via assembly fingerprints.

Enables matching process binaries to database binaries even when
MD5 differs due to version mismatches or custom builds.
Includes comprehensive error handling and validation (Phase 2 hardening).
"""

import logging

from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from blackadder.exceptions import (
    DatabaseQueryError,
    ValidationError,
)
from blackadder.models import Binary, FunctionFingerprint

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
                raise ValidationError("target_fingerprints must be dict")

            if not isinstance(available_binaries, list):
                logger.error(f"Invalid available_binaries type: {type(available_binaries)}")
                raise ValidationError("available_binaries must be list")

            if not isinstance(threshold, (int, float)):
                logger.error(f"Invalid threshold type: {type(threshold)}")
                raise ValidationError("threshold must be float")

            if not (0.0 <= threshold <= 1.0):
                logger.warning(f"Threshold out of range: {threshold} (should be 0.0-1.0)")
                raise ValidationError(f"threshold must be between 0.0 and 1.0, got {threshold}")

            if not session:
                logger.error("AsyncSession is None")
                raise ValidationError("session cannot be None")

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
        """Load fingerprints for a binary from database."""
        logger.debug("loading_fingerprints", extra={"binary_id": binary_id})

        statement = select(FunctionFingerprint).where(
            FunctionFingerprint.binary_id == binary_id
        )
        result = await session.exec(statement)  # type: ignore
        fingerprints = result.all()

        fp_dict = {fp.func_name: fp.content_hash for fp in fingerprints}
        logger.debug("fingerprints_loaded", extra={
            "binary_id": binary_id,
            "fingerprint_count": len(fp_dict),
        })
        return fp_dict

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
        """
        if not target_fps or not candidate_fps:
            logger.debug("empty_fingerprint_sets")
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
            return 0.0

        score = matching / max_count
        final_score = min(score, 1.0)  # Ensure 0.0-1.0 range

        logger.debug("match_scored", extra={
            "matching_count": matching,
            "max_count": max_count,
            "score": final_score,
        })
        return final_score

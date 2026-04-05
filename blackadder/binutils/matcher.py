"""
Binary matching via assembly fingerprints.

Enables matching process binaries to database binaries even when
MD5 differs due to version mismatches or custom builds.
"""

from sqlmodel import select
from sqlalchemy.ext.asyncio import AsyncSession

from blackadder.models import Binary, FunctionFingerprint


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
        """
        matches = []

        for binary in available_binaries:
            # Load fingerprints for this binary
            candidate_fps = await BinaryMatcher._load_fingerprints(session, binary.id)

            if not candidate_fps:
                # No fingerprints available, skip
                continue

            # Score the match
            score = BinaryMatcher.score_match(target_fingerprints, candidate_fps)

            if score >= threshold:
                matches.append((binary, score, "hash"))

        # Sort by score descending
        matches.sort(key=lambda x: x[1], reverse=True)

        return matches

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
        """
        statement = select(FunctionFingerprint).where(
            FunctionFingerprint.binary_id == binary_id
        )
        result = await session.exec(statement)
        fingerprints = result.all()

        return {fp.func_name: fp.content_hash for fp in fingerprints}

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
        """
        if not target_fps or not candidate_fps:
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
        return min(score, 1.0)  # Ensure 0.0-1.0 range

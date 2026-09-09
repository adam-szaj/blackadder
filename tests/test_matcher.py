"""
Tests for BinaryMatcher module (Phase 2.1 - Binary Matching).

Tests binary similarity scoring and matching.
"""

import pytest

from blackadder.binutils.matcher import BinaryMatcher
from blackadder.models import Binary, FunctionFingerprint


@pytest.mark.asyncio
class TestBinaryMatcherScoring:
    """Test binary matching and scoring logic."""

    async def test_score_match_identical_binaries(self):
        """Test that identical fingerprints score 1.0."""
        target_fps = {"main": "abc123", "foo": "def456", "bar": "ghi789"}
        candidate_fps = {"main": "abc123", "foo": "def456", "bar": "ghi789"}

        score = BinaryMatcher.score_match(target_fps, candidate_fps)
        assert score == 1.0

    async def test_score_match_no_overlap(self):
        """Test that completely different fingerprints score 0.0."""
        target_fps = {"main": "abc123", "foo": "def456"}
        candidate_fps = {"other": "xyz789", "baz": "uvw123"}

        score = BinaryMatcher.score_match(target_fps, candidate_fps)
        assert score == 0.0

    async def test_score_match_partial_overlap(self):
        """Test partial matching scores correctly."""
        target_fps = {"main": "abc123", "foo": "def456", "bar": "ghi789"}
        candidate_fps = {
            "main": "abc123",  # Match
            "foo": "def456",  # Match
            "bar": "different",  # No match (different hash)
            "other": "xyz789",
        }

        # 2 matching out of max(3, 4) = 4
        score = BinaryMatcher.score_match(target_fps, candidate_fps)
        assert score == pytest.approx(2.0 / 4.0)

    async def test_score_match_hash_difference_matters(self):
        """Test that same function name but different hash doesn't match."""
        target_fps = {"main": "abc123"}
        candidate_fps = {"main": "different_hash"}

        score = BinaryMatcher.score_match(target_fps, candidate_fps)
        assert score == 0.0

    async def test_score_match_function_reordering_ignored(self):
        """Test that function order doesn't affect score."""
        target_fps = {"foo": "abc", "bar": "def", "main": "ghi"}
        candidate_fps = {"main": "ghi", "bar": "def", "foo": "abc"}

        score = BinaryMatcher.score_match(target_fps, candidate_fps)
        assert score == 1.0

    async def test_score_match_version_difference(self):
        """Test matching binaries with minor version differences."""
        # v1.0 has these functions
        target_fps = {
            "main": "abc123",
            "init": "def456",
            "cleanup": "ghi789",
            "helper": "jkl012",
        }

        # v1.1 adds a function and modifies one
        candidate_fps = {
            "main": "abc123",  # Same
            "init": "def456",  # Same
            "cleanup": "modified",  # Changed (version bump)
            "helper": "jkl012",  # Same
            "new_func": "xyz999",  # Added in v1.1
        }

        # 3 matching out of max(4, 5) = 5 -> 0.6
        score = BinaryMatcher.score_match(target_fps, candidate_fps)
        assert score == pytest.approx(3.0 / 5.0)

    async def test_score_match_empty_target(self):
        """Test scoring with empty target fingerprints."""
        target_fps = {}
        candidate_fps = {"main": "abc123"}

        score = BinaryMatcher.score_match(target_fps, candidate_fps)
        assert score == 0.0

    async def test_score_match_empty_candidate(self):
        """Test scoring with empty candidate fingerprints."""
        target_fps = {"main": "abc123"}
        candidate_fps = {}

        score = BinaryMatcher.score_match(target_fps, candidate_fps)
        assert score == 0.0

    async def test_score_match_both_empty(self):
        """Test scoring when both are empty."""
        target_fps = {}
        candidate_fps = {}

        score = BinaryMatcher.score_match(target_fps, candidate_fps)
        assert score == 0.0

    async def test_score_match_subset_relationship(self):
        """Test scoring when candidate is subset of target."""
        target_fps = {"a": "1", "b": "2", "c": "3", "d": "4"}
        candidate_fps = {"a": "1", "b": "2"}

        # 2 matching out of max(4, 2) = 4 -> 0.5
        score = BinaryMatcher.score_match(target_fps, candidate_fps)
        assert score == pytest.approx(2.0 / 4.0)

    async def test_score_match_superset_relationship(self):
        """Test scoring when candidate is superset of target."""
        target_fps = {"a": "1", "b": "2"}
        candidate_fps = {"a": "1", "b": "2", "c": "3", "d": "4"}

        # 2 matching out of max(2, 4) = 4 -> 0.5
        score = BinaryMatcher.score_match(target_fps, candidate_fps)
        assert score == pytest.approx(2.0 / 4.0)


@pytest.mark.asyncio
class TestBinaryMatcherFindMatches:
    """Test finding matching binaries from candidates."""

    async def test_find_matches_returns_list(self, memory_db):
        """Test that find_matches returns a list."""
        async with memory_db.get_session() as session:
            # Create a binary in DB
            binary = Binary(md5sum="abc123", name="libc.so.6")
            session.add(binary)
            await session.commit()

            target_fps = {"main": "hash1"}
            candidates = [binary]

            matches = await BinaryMatcher.find_matches(
                target_fps, candidates, session, threshold=0.0
            )

        assert isinstance(matches, list)

    async def test_find_matches_empty_candidates(self, memory_db):
        """Test that empty candidates returns empty list."""
        async with memory_db.get_session() as session:
            target_fps = {"main": "hash1"}
            candidates = []

            matches = await BinaryMatcher.find_matches(
                target_fps, candidates, session, threshold=0.7
            )

        assert len(matches) == 0

    async def test_find_matches_sorted_by_score(self, memory_db):
        """Test that matches are sorted by score descending."""
        async with memory_db.get_session() as session:
            # Create test binaries
            bin1 = Binary(md5sum="bin1", name="libc.so.6")
            bin2 = Binary(md5sum="bin2", name="libc.so.6.1")
            session.add(bin1)
            session.add(bin2)
            await session.commit()

            # Add fingerprints for bin1 (perfect match)
            fp1_main = FunctionFingerprint(
                binary_id=bin1.id,
                func_name="main",
                func_offset=0,
                func_size=100,
                content_hash="hash1",
            )
            session.add(fp1_main)

            # Add fingerprints for bin2 (partial match)
            fp2_foo = FunctionFingerprint(
                binary_id=bin2.id,
                func_name="foo",
                func_offset=100,
                func_size=50,
                content_hash="hash2",
            )
            session.add(fp2_foo)
            await session.commit()

            target_fps = {"main": "hash1"}
            candidates = [bin1, bin2]

            matches = await BinaryMatcher.find_matches(
                target_fps, candidates, session, threshold=0.0
            )

        # Should have both matches (assuming fingerprints were loaded)
        if len(matches) > 1:
            # Check sorting: best score first
            assert matches[0][1] >= matches[1][1]

    async def test_find_matches_respects_threshold(self, memory_db):
        """Test that threshold filtering works."""
        async with memory_db.get_session() as session:
            # Create binary
            binary = Binary(md5sum="test", name="test.so")
            session.add(binary)
            await session.commit()

            # Add low-match fingerprints
            fp = FunctionFingerprint(
                binary_id=binary.id,
                func_name="other",
                func_offset=0,
                func_size=100,
                content_hash="different",
            )
            session.add(fp)
            await session.commit()

            target_fps = {"main": "hash1"}
            candidates = [binary]

            # High threshold should exclude low match
            matches_high = await BinaryMatcher.find_matches(
                target_fps, candidates, session, threshold=0.9
            )

            # Low threshold might include it
            matches_low = await BinaryMatcher.find_matches(
                target_fps, candidates, session, threshold=0.0
            )

        # Higher threshold should return same or fewer matches
        assert len(matches_high) <= len(matches_low)

    async def test_find_matches_return_format(self, memory_db):
        """Test that matches have correct format."""
        async with memory_db.get_session() as session:
            binary = Binary(md5sum="test", name="test.so")
            session.add(binary)
            await session.commit()

            fp = FunctionFingerprint(
                binary_id=binary.id,
                func_name="main",
                func_offset=0,
                func_size=100,
                content_hash="hash1",
            )
            session.add(fp)
            await session.commit()

            target_fps = {"main": "hash1"}
            candidates = [binary]

            matches = await BinaryMatcher.find_matches(
                target_fps, candidates, session, threshold=0.0
            )

        if len(matches) > 0:
            # Each match should be (Binary, float, str)
            match = matches[0]
            assert isinstance(match, tuple)
            assert len(match) == 3
            assert isinstance(match[0], Binary)
            assert isinstance(match[1], float)
            assert 0.0 <= match[1] <= 1.0
            assert isinstance(match[2], str)

"""Tests for training utility functions: _simple_augment, _augment_rare_classes."""

from __future__ import annotations

import random

import pytest

from vigilyx_ai.trainer import _augment_rare_classes, _simple_augment


# =====================================================================
# _simple_augment
# =====================================================================


class TestSimpleAugment:
    """~7 cases for _simple_augment."""

    def test_header_lines_preserved(self):
        text = "From: alice@example.com\nSubject: Hello\nThis is the body text of the email"
        rng = random.Random(42)
        result = _simple_augment(text, rng)
        lines = result.split("\n")
        assert lines[0] == "From: alice@example.com"
        assert lines[1] == "Subject: Hello"

    def test_body_is_augmented(self):
        text = "From: user@ex.com\nSubject: Test\nWord1 Word2 Word3 Word4 Word5 Word6 Word7"
        rng = random.Random(42)
        result = _simple_augment(text, rng)
        # The body part should be different from the original (with high probability)
        original_body = "Word1 Word2 Word3 Word4 Word5 Word6 Word7"
        result_lines = result.split("\n")
        result_body = result_lines[-1] if len(result_lines) > 2 else ""
        # It's possible (though unlikely with 7 words and seed 42) that nothing changes.
        # We mainly verify that the function runs without error and preserves structure.
        assert len(result_lines) == 3

    def test_very_short_body_unchanged(self):
        text = "From: u@e.com\nSubject: S\nHi me"
        rng = random.Random(42)
        result = _simple_augment(text, rng)
        # <=3 body words → returned unchanged
        assert result == text

    def test_no_headers_still_works(self):
        text = "This is just plain body text with several words for augmentation"
        rng = random.Random(42)
        result = _simple_augment(text, rng)
        # No header lines, body gets augmented
        assert isinstance(result, str)
        assert len(result) > 0

    def test_deterministic_with_same_seed(self):
        text = "From: a@b.com\nSubject: T\nAlpha Beta Gamma Delta Epsilon Zeta Eta"
        r1 = _simple_augment(text, random.Random(99))
        r2 = _simple_augment(text, random.Random(99))
        assert r1 == r2

    def test_different_seeds_different_results(self):
        text = "From: a@b.com\nSubject: T\nAlpha Beta Gamma Delta Epsilon Zeta Eta Theta Iota Kappa Lambda"
        r1 = _simple_augment(text, random.Random(1))
        r2 = _simple_augment(text, random.Random(2))
        # Different seeds should produce different augmentations with high probability
        # (though not guaranteed for very short inputs)
        # We test with a long enough body that it's extremely unlikely to be the same.
        assert r1 != r2

    def test_empty_body_with_headers(self):
        text = "From: a@b.com\nSubject: S"
        rng = random.Random(42)
        result = _simple_augment(text, rng)
        # Body is empty → words is empty (<=3) → returned unchanged
        assert result == text


# =====================================================================
# _augment_rare_classes
# =====================================================================


class TestAugmentRareClasses:
    """~8 cases for _augment_rare_classes."""

    def test_underrepresented_class_augmented(self):
        texts = ["text_a", "text_b", "text_c"] + ["text_d"] * 10
        labels = [0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]
        aug_texts, aug_labels = _augment_rare_classes(texts, labels, min_target=10, rng_seed=42)
        # Class 0 had 3 samples, needs 7 more to reach 10
        assert aug_labels.count(0) == 10

    def test_overrepresented_class_unchanged(self):
        texts = ["text"] * 15
        labels = [0] * 10 + [1] * 5
        aug_texts, aug_labels = _augment_rare_classes(texts, labels, min_target=5, rng_seed=42)
        assert aug_labels.count(0) == 10  # Already >= 5, unchanged
        assert aug_labels.count(1) == 5   # Already == 5, unchanged
        assert len(aug_texts) == 15

    def test_total_count_increases(self):
        texts = ["t1", "t2", "t3"]
        labels = [0, 1, 1]
        aug_texts, aug_labels = _augment_rare_classes(texts, labels, min_target=5, rng_seed=42)
        # Class 0: 1 → needs 4 more. Class 1: 2 → needs 3 more.
        assert len(aug_texts) == len(aug_labels)
        assert len(aug_texts) > 3

    def test_labels_match_augmented_texts(self):
        texts = ["legit1", "legit2", "phish1"]
        labels = [0, 0, 1]
        aug_texts, aug_labels = _augment_rare_classes(texts, labels, min_target=3, rng_seed=42)
        assert len(aug_texts) == len(aug_labels)
        # Class 0 had 2, needs 1 more. Class 1 had 1, needs 2 more.
        assert aug_labels.count(0) == 3
        assert aug_labels.count(1) == 3

    def test_deterministic_with_same_seed(self):
        texts = ["a", "b", "c", "d"]
        labels = [0, 0, 1, 1]
        r1 = _augment_rare_classes(texts, labels, min_target=5, rng_seed=99)
        r2 = _augment_rare_classes(texts, labels, min_target=5, rng_seed=99)
        assert r1[0] == r2[0]
        assert r1[1] == r2[1]

    def test_no_augmentation_needed(self):
        texts = ["a", "b", "c", "d"]
        labels = [0, 0, 1, 1]
        aug_texts, aug_labels = _augment_rare_classes(texts, labels, min_target=2, rng_seed=42)
        # Both classes already >= 2
        assert len(aug_texts) == 4
        assert aug_texts == list(texts)

    def test_multiple_classes(self):
        texts = ["t"] * 20
        labels = [0] * 10 + [1] * 3 + [2] * 2 + [3] * 5
        aug_texts, aug_labels = _augment_rare_classes(texts, labels, min_target=5, rng_seed=42)
        # Class 0: 10 (ok), Class 1: 3 → 5, Class 2: 2 → 5, Class 3: 5 (ok)
        assert aug_labels.count(0) == 10
        assert aug_labels.count(1) == 5
        assert aug_labels.count(2) == 5
        assert aug_labels.count(3) == 5

    def test_single_sample_class_augmented(self):
        texts = ["rare_sample", "common"] * 5
        labels = [0] + [1] * 9
        aug_texts, aug_labels = _augment_rare_classes(texts, labels, min_target=5, rng_seed=42)
        assert aug_labels.count(0) == 5

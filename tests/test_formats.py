"""Pattern-table checks that need no Hermes install (run on every OS in CI)."""

from __future__ import annotations

import re

import pytest

from conftest import PLUGIN_DIR, REPO_ROOT, SAMPLES

# How Hermes wraps the joined prefix patterns (agent.redact._compile_prefix_matcher).
_BOUNDED = "(?<![A-Za-z0-9_-])({})(?![A-Za-z0-9_-])"


def _matcher(patterns) -> re.Pattern[str]:
    return re.compile(_BOUNDED.format("|".join(patterns)))


def test_every_pattern_has_samples(pack):
    assert set(SAMPLES) == set(pack.patterns.PATTERNS)


def test_patterns_are_unique(pack):
    assert len(set(pack.patterns.PATTERNS)) == len(pack.patterns.PATTERNS)


@pytest.mark.parametrize("pattern", sorted(SAMPLES))
def test_pattern_is_joinable(pattern):
    # Joined into one alternation: a capturing group would shift Hermes's group(1),
    # an inline flag is an error mid-pattern.
    assert re.compile(pattern).groups == 0
    assert "(?i" not in pattern and "(?-i" not in pattern
    assert re.match(r"(?:[A-Za-z0-9_~-]|\\\.){2,}", pattern), "needs a literal vendor prefix"


@pytest.mark.parametrize("pattern", sorted(SAMPLES))
def test_samples_match_whole(pattern):
    for token in SAMPLES[pattern]:
        assert re.fullmatch(pattern, token), token
        found = _matcher([pattern]).search(f"error: request with {token} was rejected")
        assert found and found.group(1) == token


@pytest.mark.parametrize("text", [
    "see docs/hvs.md and the dp.pt. prefix table",
    "a shpat_ token is 32 hex characters",
    "pul-request, ico-sizes and dapi-docs are not credentials",
    "sha256~short and tk-us-east are ordinary words",
    "NRAK-12 is a ticket id",
    "hvb.batch and hvs.service are Vault token types",
    "api_org_settings_page",
])
def test_prose_with_vendor_prefixes_is_untouched(pack, text):
    assert _matcher(pack.patterns.PATTERNS).search(text) is None


def test_longer_run_is_not_a_partial_match(pack):
    # Fixed-length formats stay anchored: a 33-hex run after shpat_ is not a Shopify token.
    assert _matcher(pack.patterns.PATTERNS).search("shpat_" + "a" * 33) is None


def test_manifest_counts_the_formats(pack):
    manifest = (PLUGIN_DIR / "plugin.yaml").read_text(encoding="utf-8-sig")
    assert f" {len(pack.patterns.FORMATS)} more vendor credential formats" in manifest


def test_readme_lists_every_format(pack):
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8-sig")
    for fmt in pack.patterns.FORMATS:
        cell = fmt.pattern.replace("|", "\\|")  # GFM table cells escape the pipe
        assert f"| {fmt.vendor} | {fmt.token} | `{cell}` |" in readme, fmt


def test_plugin_readme_is_the_repo_readme():
    # The catalog page renders <subdir>/README.md at the pinned commit.
    root = (REPO_ROOT / "README.md").read_bytes()
    assert (PLUGIN_DIR / "README.md").read_bytes() == root

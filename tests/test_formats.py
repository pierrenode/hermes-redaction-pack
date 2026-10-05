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
    "lsv2_pt_ and lsv2_sk_ are LangSmith prefixes; pcsk_ is Pinecone's; wandb_v1_ is W&B's",
    "dckr_pat_ and dckr_oat_ are Docker Hub prefixes; figd_ and figp_ are Figma's; sbp_ is Supabase's",
    "set TS_AUTHKEY=tskey-auth-XXXX-YYYY, see tskey-api- and tskey-client- in the Tailscale docs",
    "AKCp keys and cmVmdGtu reference tokens come from JFrog Artifactory",
    "ATATT and ATCTT3xFfG are Atlassian prefixes; pat-na1- is HubSpot's; phx_ is PostHog's; cfk_ is Cloudflare's",
    "CCIPAT_, bkua_, CFPAT-, BBDC-, sqco_, slk_, rootly_ and apify_api_ are token prefixes",
    "FLWSECK- and FLWSECK_TEST- are Flutterwave's; p8e- is Adobe's; NRIQ- is New Relic's; ramp_sec_ is Ramp's",
    "see ATATT3xFfGF0-token-docs and pat-na1-docs for details",
])
def test_prose_with_vendor_prefixes_is_untouched(pack, text):
    assert _matcher(pack.patterns.PATTERNS).search(text) is None


def test_longer_run_is_not_a_partial_match(pack):
    # Fixed-length formats stay anchored: a 33-hex run after shpat_ is not a Shopify token.
    assert _matcher(pack.patterns.PATTERNS).search("shpat_" + "a" * 33) is None
    assert _matcher(pack.patterns.PATTERNS).search("dckr_pat_" + "a" * 28) is None
    assert _matcher(pack.patterns.PATTERNS).search("sbp_" + "a" * 41) is None
    assert _matcher(pack.patterns.PATTERNS).search("AKCp" + "a" * 70) is None
    assert _matcher(pack.patterns.PATTERNS).search("cmVmdGtu" + "a" * 57) is None
    # Artifactory reference tokens are always 64 characters: a shorter run is not one either.
    assert _matcher(pack.patterns.PATTERNS).search("cmVmdGtu" + "a" * 55) is None
    assert _matcher(pack.patterns.PATTERNS).search("rootly_" + "a" * 65) is None
    assert _matcher(pack.patterns.PATTERNS).search("phx_" + "a" * 49) is None
    assert _matcher(pack.patterns.PATTERNS).search("BBDC-" + "a" * 51) is None
    assert _matcher(pack.patterns.PATTERNS).search("FLWSECK-" + "a" * 32 + "-Y") is None


def test_bodies_keep_their_alphabet(pack):
    m = _matcher(pack.patterns.PATTERNS)
    # Cloudflare's cfk_ keys end in 8 hex characters; Buildkite's are lowercase; Rootly's and
    # Sourcegraph Cody's are hex; Flutterwave test secrets use a-h and digits only.
    assert m.search("cfk_" + "a" * 40 + "g" * 8) is None
    assert m.search("bkua_" + "A" * 40) is None
    assert m.search("rootly_" + "g" * 64) is None
    assert m.search("slk_" + "g" * 64) is None
    assert m.search("FLWSECK_TEST-" + "z" * 32 + "-X") is None
    # Atlassian tokens end in "=" and an 8-character checksum.
    assert m.search("ATATT3xFfGF0" + "a" * 180) is None
    assert m.search("ATCTT3xFfGN0" + "a" * 180) is None


@pytest.mark.parametrize("token", [
    # One body character more than the format allows, inserted where the fixed-length run is.
    "cfk_" + "a" * 41 + "0" * 8,
    "NRIQ-" + "a" * 26,
    "ATATT3xFfGF0" + "a" * 100 + "=" + "a" * 9,
    "ATCTT3xFfGN0" + "a" * 100 + "=" + "a" * 9,
    "CCIPAT_" + "a" * 23 + "_" + "0" * 40,
    "CCIPAT_" + "a" * 22 + "_" + "0" * 41,
    "bkua_" + "a" * 41,
    "sqco_" + "a" * 60,
    "slk_" + "0" * 65,
    "CFPAT-" + "a" * 44,
    "apify_api_" + "a" * 37,
    "p8e-" + "a" * 33,
    "pat-na1-" + "a" * 9 + "-aaaa-aaaa-aaaa-" + "a" * 12,
    "pat-eu1-" + "a" * 8 + "-aaaa-aaaa-aaaa-" + "a" * 13,
    "FLWSECK-" + "a" * 33 + "-X",
    "FLWSECK_TEST-" + "a" * 33 + "-X",
    "ramp_sec_" + "a" * 49,
])
def test_one_character_too_many_is_not_a_token(pack, token):
    assert _matcher(pack.patterns.PATTERNS).search(token) is None


def test_supabase_token_body_is_hex(pack):
    # The Supabase CLI accepts only lowercase hex after the prefix.
    assert _matcher(pack.patterns.PATTERNS).search("sbp_" + "g" * 40) is None


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

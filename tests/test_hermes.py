"""The pack against a real Hermes: run with Hermes importable (CI checks out the
release floor and main). Every call uses ``force=True`` so the results do not depend
on the ``security.redact_secrets`` setting of the machine running the tests."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from agent.redact import _reset_plugin_redaction_patterns, redact_sensitive_text, register_redaction_patterns
from conftest import PLUGIN_DIR, SAMPLES

ALL_TOKENS = [token for tokens in SAMPLES.values() for token in tokens]


@pytest.fixture(autouse=True)
def _clean_registry():
    _reset_plugin_redaction_patterns()
    yield
    _reset_plugin_redaction_patterns()


def _line(token: str) -> str:
    return f"deploy failed: 401 Unauthorized for {token} (retrying)"


@pytest.mark.parametrize("token", ALL_TOKENS)
def test_hermes_alone_leaks_the_token(token):
    # The gap the pack exists for: without it the secret end of the token reaches the
    # output (whole, or past the first "/" where a generic rule stops). If this fails,
    # Hermes masks the format itself and the pattern can leave the pack in a later release.
    assert token[-16:] in redact_sensitive_text(_line(token), force=True)


def test_hermes_accepts_every_pattern(pack):
    assert register_redaction_patterns(list(pack.patterns.PATTERNS), source="test") == len(pack.patterns.PATTERNS)


@pytest.mark.parametrize("token", ALL_TOKENS)
def test_registered_pack_masks_the_token(pack, token):
    register_redaction_patterns(list(pack.patterns.PATTERNS), source="test")
    out = redact_sensitive_text(_line(token), force=True)
    assert token not in out
    assert out.startswith("deploy failed: 401 Unauthorized for ") and out.endswith(" (retrying)")


def test_file_reads_get_the_non_reusable_sentinel(pack):
    register_redaction_patterns(list(pack.patterns.PATTERNS), source="test")
    token = SAMPLES[r"pul-[a-f0-9]{40}"][0]
    out = redact_sensitive_text(f"PULUMI_ACCESS_TOKEN={token}\n", force=True, file_read=True)
    assert token not in out and "redacted" in out


def test_builtins_still_mask(pack):
    register_redaction_patterns(list(pack.patterns.PATTERNS), source="test")
    builtin = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
    assert builtin not in redact_sensitive_text(_line(builtin), force=True)


def test_hermes_source_tree_has_no_false_positives(pack):
    # Hermes's own code and docs are full of vendor names, prefixes and hex: the pack
    # must not change a byte of them.
    import agent

    root = Path(agent.__file__).resolve().parent.parent
    files = [p for p in root.rglob("*") if p.suffix in {".py", ".md"} and p.is_file()
             and not ({"tests", "node_modules", ".venv", ".git"} & set(p.relative_to(root).parts))]
    assert len(files) > 500
    baseline = {p: redact_sensitive_text(p.read_text(encoding="utf-8-sig", errors="replace"), force=True)
                for p in files}
    register_redaction_patterns(list(pack.patterns.PATTERNS), source="test")
    changed = [str(p.relative_to(root)) for p in files
               if redact_sensitive_text(p.read_text(encoding="utf-8-sig", errors="replace"), force=True) != baseline[p]]
    assert changed == []


_PROBE = """
import json, sys
from hermes_cli.plugins import discover_plugins, get_plugin_manager
from agent.redact import redact_sensitive_text
discover_plugins()
plugins = {p["name"]: p for p in get_plugin_manager().list_plugins()}
tokens = json.loads(sys.argv[1])
masked = [t not in redact_sensitive_text("x " + t + " y", force=True) for t in tokens]
print(json.dumps({"plugin": plugins.get("redaction-pack"), "masked": masked}))
"""


def test_installed_and_enabled_pack_masks_in_a_fresh_hermes(tmp_path):
    # Real discovery: plugin copied under HERMES_HOME/plugins, enabled with the CLI, then
    # loaded by discover_plugins() in a separate process (manifest, requires_hermes gate,
    # package import, register()).
    home = tmp_path / "hermes-home"
    shutil.copytree(PLUGIN_DIR, home / "plugins" / "redaction-pack")
    env = {k: v for k, v in os.environ.items() if not k.startswith(("HERMES_", "OPENAI", "ANTHROPIC"))}
    env["HERMES_HOME"] = str(home)
    subprocess.run([sys.executable, "-m", "hermes_cli.main", "plugins", "enable", "redaction-pack"],
                   env=env, check=True, capture_output=True, text=True, timeout=180)
    tokens = [tokens[0] for tokens in SAMPLES.values()]
    probe = subprocess.run([sys.executable, "-c", _PROBE, json.dumps(tokens)],
                           env=env, check=True, capture_output=True, text=True, timeout=180)
    result = json.loads(probe.stdout.strip().splitlines()[-1])
    plugin = result["plugin"]
    assert plugin is not None, probe.stderr
    assert plugin["enabled"] and not plugin["error"], plugin
    assert all(result["masked"])

"""Shared fixtures: the pack loaded the way Hermes loads it, and synthetic tokens.

Tokens are assembled at test time from a prefix and a deterministic fill, so no
credential-shaped literal is ever committed (and nothing trips push protection).
"""

from __future__ import annotations

import importlib.util
import string
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
PLUGIN_DIR = REPO_ROOT / "redaction-pack"

HEX = "0123456789abcdef"
UPPER_HEX = "0123456789ABCDEF"
LOWER_ALNUM = string.ascii_lowercase + string.digits
UPPER_ALNUM = string.ascii_uppercase + string.digits
LETTERS = string.ascii_letters
ALNUM = string.ascii_letters + string.digits
URLSAFE = ALNUM + "_-"
BASE64 = ALNUM + "+/"


def fill(chars: str, n: int, seed: int = 0) -> str:
    """``n`` characters drawn from ``chars`` in a fixed, mixed-looking order."""
    return "".join(chars[(i * 7 + seed * 13 + 3) % len(chars)] for i in range(n))


def load_pack():
    """Import the plugin package from its directory, as Hermes's loader does."""
    name = "redaction_pack_under_test"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(
        name, PLUGIN_DIR / "__init__.py", submodule_search_locations=[str(PLUGIN_DIR)])
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _samples() -> dict[str, list[str]]:
    """Pattern -> one synthetic token per alternative the pattern accepts."""
    s = {
        r"A3-[A-Z0-9]{6}-(?:[A-Z0-9]{11}|[A-Z0-9]{6}-[A-Z0-9]{5})-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}":
            ["A3-" + "-".join(fill(UPPER_ALNUM, n, i) for i, n in enumerate((6, 11, 5, 5, 5))),
             "A3-" + "-".join(fill(UPPER_ALNUM, n, i) for i, n in enumerate((6, 6, 5, 5, 5, 5)))],
        r"hvs\.[A-Za-z0-9_-]{90,120}": ["hvs." + fill(URLSAFE, 95)],
        r"hvb\.[A-Za-z0-9_-]{138,300}": ["hvb." + fill(URLSAFE, 150)],
        r"dp\.(?:ct|pt|sa|said|scim|audit)\.[A-Za-z0-9]{40,44}":
            [f"dp.{kind}." + fill(ALNUM, 43, i)
             for i, kind in enumerate(("ct", "pt", "sa", "said", "scim", "audit"))],
        r"dp\.st\.(?:[a-z0-9_-]{2,35}\.)?[A-Za-z0-9]{40,44}":
            ["dp.st.dev." + fill(ALNUM, 43), "dp.st." + fill(ALNUM, 44, 1)],
        r"ABSK[A-Za-z0-9+/]{109,269}={0,2}": ["ABSK" + fill(BASE64, 132) + "="],
        r"bedrock-api-key-YmVkcm9jay5hbWF6b25hd3MuY29t[A-Za-z0-9+/]{20,}={0,2}":
            ["bedrock-api-key-YmVkcm9jay5hbWF6b25hd3MuY29t" + fill(BASE64, 160) + "=="],
        r"LTAI[A-Za-z0-9]{20}": ["LTAI" + fill(ALNUM, 20)],
        r"dor_v1_[a-f0-9]{64}": ["dor_v1_" + fill(HEX, 64)],
        r"fo1_[A-Za-z0-9_-]{43}": ["fo1_" + fill(URLSAFE, 43)],
        r"fm1[ar]_[A-Za-z0-9+/]{100,}={0,3}":
            ["fm1a_" + fill(BASE64, 120), "fm1r_" + fill(BASE64, 140, 1) + "=="],
        r"fm2_[A-Za-z0-9+/]{100,}={0,3}": ["fm2_" + fill(BASE64, 180) + "="],
        r"HRKU-AA[A-Za-z0-9_-]{58}": ["HRKU-AA" + fill(URLSAFE, 58)],
        r"sha256~[A-Za-z0-9_-]{43}": ["sha256~" + fill(URLSAFE, 43)],
        r"tk-us-[A-Za-z0-9_-]{48}": ["tk-us-" + fill(URLSAFE, 48)],
        r"pul-[a-f0-9]{40}": ["pul-" + fill(HEX, 40)],
        r"ico-[A-Za-z0-9]{32}": ["ico-" + fill(ALNUM, 32)],
        r"dapi[a-f0-9]{32}(?:-[0-9])?": ["dapi" + fill(HEX, 32), "dapi" + fill(HEX, 32, 1) + "-2"],
        r"pscale_(?:tkn|oauth|pw)_[A-Za-z0-9_.=-]{32,64}":
            [f"pscale_{kind}_" + fill(ALNUM, 43, i) for i, kind in enumerate(("tkn", "oauth", "pw"))],
        r"sbp_(?:oauth_|v0_)?[a-f0-9]{40}":
            ["sbp_" + fill(HEX, 40), "sbp_oauth_" + fill(HEX, 40, 1), "sbp_v0_" + fill(HEX, 40, 2)],
        r"tskey-(?:api|auth|client|scim|webhook)-[A-Za-z0-9_]+-[A-Za-z0-9_]{16,}":
            [f"tskey-{kind}-k" + fill(ALNUM, 10, i) + "CNTRL-" + fill(ALNUM, 18 + 5 * i, i + 1)
             for i, kind in enumerate(("api", "auth", "client", "scim", "webhook"))]
            + ["tskey-auth-k" + fill(ALNUM, 6, 5) + "_" + fill(ALNUM, 5, 6) + "-" + fill(ALNUM, 9, 7) + "_" + fill(ALNUM, 9, 8)],
        r"api_org_[A-Za-z]{34}": ["api_org_" + fill(LETTERS, 34)],
        r"lsv2_(?:pt|sk)_[a-f0-9]{32}_[a-f0-9]{10}":
            ["lsv2_pt_" + fill(HEX, 32) + "_" + fill(HEX, 10, 1),
             "lsv2_sk_" + fill(HEX, 32, 2) + "_" + fill(HEX, 10, 3)],
        r"pcsk_[A-Za-z0-9]{5,6}_[A-Za-z0-9]{63}":
            ["pcsk_" + fill(ALNUM, 5) + "_" + fill(ALNUM, 63, 1),
             "pcsk_" + fill(ALNUM, 6, 2) + "_" + fill(ALNUM, 63, 3)],
        r"wandb_v1_[A-Za-z0-9]{27}_[A-Za-z0-9]{49}":
            ["wandb_v1_" + fill(ALNUM, 27) + "_" + fill(ALNUM, 49, 1)],
        r"glc_[A-Za-z0-9+/]{32,400}={0,3}": ["glc_" + fill(BASE64, 120) + "="],
        r"glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}": ["glsa_" + fill(ALNUM, 32) + "_" + fill(HEX, 8)],
        r"sntryu_[a-f0-9]{64}": ["sntryu_" + fill(HEX, 64)],
        r"sntrys_eyJ[A-Za-z0-9+/]{30,400}={0,2}_[A-Za-z0-9+/]{43}":
            ["sntrys_eyJ" + fill(BASE64, 120) + "=_" + fill(BASE64, 43, 1)],
        r"dt0c01\.[A-Za-z0-9]{24}\.[A-Za-z0-9]{64}":
            ["dt0c01." + fill(UPPER_ALNUM, 24) + "." + fill(ALNUM, 64)],
        r"NRAK-[A-Za-z0-9]{27}": ["NRAK-" + fill(UPPER_ALNUM, 27)],
        r"NRII-[A-Za-z0-9_-]{32}": ["NRII-" + fill(URLSAFE, 32)],
        r"PMAK-[a-fA-F0-9]{24}-[a-fA-F0-9]{34}": ["PMAK-" + fill(HEX, 24) + "-" + fill(HEX, 34, 1)],
        r"sgp_(?:[a-fA-F0-9]{16}_|local_)?[a-fA-F0-9]{40}":
            ["sgp_" + fill(HEX, 16) + "_" + fill(HEX, 40, 1),
             "sgp_local_" + fill(HEX, 40, 2),
             "sgp_" + fill(HEX, 40, 3)],
        r"pnu_[A-Za-z0-9]{36}": ["pnu_" + fill(ALNUM, 36)],
        r"rdme_[a-z0-9]{70}": ["rdme_" + fill(LOWER_ALNUM, 70)],
        r"rubygems_[a-f0-9]{48}": ["rubygems_" + fill(HEX, 48)],
        r"CLOJARS_[A-Za-z0-9]{60}": ["CLOJARS_" + fill(ALNUM, 60)],
        r"AKCp[A-Za-z0-9]{69}": ["AKCp" + fill(ALNUM, 69)],
        r"cmVmdGtu[A-Za-z0-9]{56}": ["cmVmdGtu" + fill(ALNUM, 56)],
        r"tfp_[A-Za-z0-9_.=-]{59}": ["tfp_" + fill(ALNUM, 59)],
        r"fio-u-[A-Za-z0-9_=-]{64}": ["fio-u-" + fill(URLSAFE, 64)],
        r"dckr_pat_[A-Za-z0-9_-]{27}": ["dckr_pat_" + fill(ALNUM, 13) + "-_" + fill(ALNUM, 12, 1)],
        r"dckr_oat_[A-Za-z0-9_-]{32}": ["dckr_oat_" + fill(ALNUM, 15, 2) + "_-" + fill(ALNUM, 15, 3)],
        r"figd_[A-Za-z0-9_-]{40}": ["figd_" + fill(ALNUM, 19) + "-_" + fill(ALNUM, 19, 1)],
        r"figp_[A-Za-z0-9_=-]{40,54}": ["figp_" + fill(ALNUM, 42), "figp_" + fill(URLSAFE, 52, 1) + "=="],
        r"xoxe-[0-9]-[A-Za-z0-9]{146}": ["xoxe-1-" + fill(ALNUM, 146)],
        r"shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}":
            [f"shp{kind}_" + fill(HEX, 32, i) for i, kind in enumerate(("at", "ca", "pa", "ss"))],
        r"sq0atp-[A-Za-z0-9_-]{22,60}": ["sq0atp-" + fill(URLSAFE, 22)],
        r"shippo_(?:live|test)_[a-fA-F0-9]{40}":
            ["shippo_live_" + fill(HEX, 40), "shippo_test_" + fill(HEX, 40, 1)],
        r"duffel_(?:test|live)_[A-Za-z0-9_=-]{43}":
            ["duffel_test_" + fill(ALNUM, 43), "duffel_live_" + fill(ALNUM, 43, 1)],
        r"EZ[AT]K[A-Za-z0-9]{54}": ["EZAK" + fill(ALNUM, 54), "EZTK" + fill(ALNUM, 54, 1)],
        r"xkeysib-[a-f0-9]{64}-[A-Za-z0-9]{16}": ["xkeysib-" + fill(HEX, 64) + "-" + fill(ALNUM, 16, 1)],
    }
    return s


SAMPLES = _samples()


@pytest.fixture(scope="session")
def pack():
    return load_pack()

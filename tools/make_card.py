"""Render docs/card.png, the 1200x600 catalog card.

The before/after lines are real output: the pack is registered with Hermes's redactor and
each line is passed through ``agent.redact.redact_sensitive_text``. Run with Hermes importable:

    PYTHONPATH=/path/to/hermes-agent python tools/make_card.py --fonts /path/to/fonts

Fonts (OFL), from google/fonts at commit 9710da1eacb3be272583c3224dcb70f9da6eadbb:
    ofl/dmsans/DMSans[opsz,wght].ttf          -> DMSans.ttf
        sha256 8cd08d97e89c24d0aa92edd2f0f4c8ee6195eee9b7c9f154865a58b02f0c1c0d
    ofl/jetbrainsmono/JetBrainsMono[wght].ttf -> JetBrainsMono.ttf
        sha256 48715a42ec242c21e9f02692891e147d022299a52e48d5e413e1a942193ffeda

The plugin page hero crops the card to rows 110-490 at its widest; everything drawn here
must sit inside rows 132-468 (about 20px of air on each side), and the script asserts it.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import string
import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent.parent
W, H = 1200, 600
BAND = (132, 468)
MARGIN_X = 96
FONT_SHA256 = {
    "DMSans.ttf": "8cd08d97e89c24d0aa92edd2f0f4c8ee6195eee9b7c9f154865a58b02f0c1c0d",
    "JetBrainsMono.ttf": "48715a42ec242c21e9f02692891e147d022299a52e48d5e413e1a942193ffeda",
}

BG = (15, 17, 21)
PANEL = (24, 27, 33)
PANEL_EDGE = (44, 48, 56)
TEXT = (236, 238, 241)
MUTED = (150, 156, 166)
LEAK = (240, 128, 120)
SAFE = (126, 214, 160)

ALNUM = string.ascii_letters + string.digits
HEX = "0123456789abcdef"


def fill(chars: str, n: int, seed: int = 0) -> str:
    return "".join(chars[(i * 7 + seed * 13 + 3) % len(chars)] for i in range(n))


def load_pack():
    plugin_dir = ROOT / "redaction-pack"
    spec = importlib.util.spec_from_file_location(
        "redaction_pack_card", plugin_dir / "__init__.py", submodule_search_locations=[str(plugin_dir)])
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def font(path: Path, size: int, weight: int, opsz: int | None = None) -> ImageFont.FreeTypeFont:
    f = ImageFont.truetype(str(path), size)
    f.set_variation_by_axes([opsz, weight] if opsz is not None else [weight])
    return f


def clip(draw: ImageDraw.ImageDraw, text: str, f: ImageFont.FreeTypeFont, width: int) -> str:
    if draw.textlength(text, font=f) <= width:
        return text
    while text and draw.textlength(text + "…", font=f) > width:
        text = text[:-1]
    return text + "…"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fonts", type=Path, required=True)
    parser.add_argument("--out", type=Path, default=ROOT / "docs" / "card.png")
    args = parser.parse_args()
    for name, digest in FONT_SHA256.items():
        actual = hashlib.sha256((args.fonts / name).read_bytes()).hexdigest()
        assert actual == digest, f"{name}: sha256 {actual} != pinned {digest}"

    from agent.redact import redact_sensitive_text, register_redaction_patterns

    samples = [
        "vault login: hvs." + fill(ALNUM + "_-", 95),
        "doppler run --config prod: dp.st.prod." + fill(ALNUM, 43, 1),
        "401 from shop: shpat_" + fill(HEX, 32, 2),
    ]
    # Each line must leak without the pack, so the card never credits a built-in mask to it.
    for line in samples:
        assert redact_sensitive_text(line, force=True) == line, f"Hermes already masks: {line[:30]}"

    pack = load_pack()
    assert register_redaction_patterns(list(pack.patterns.PATTERNS), source="card") == len(pack.patterns.PATTERNS)
    pairs = []
    for line in samples:
        out = redact_sensitive_text(line, force=True)
        assert out != line, f"pack did not mask: {line[:30]}"
        pairs.append((line, out))

    dm = args.fonts / "DMSans.ttf"
    mono = args.fonts / "JetBrainsMono.ttf"
    title_f = font(dm, 58, 700, 36)
    sub_f = font(dm, 26, 400, 14)
    code_f = font(mono, 21, 400)

    ink = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    d = ImageDraw.Draw(ink)
    # The title's line box starts ~17px above its ink; this centres the ink in BAND.
    y = BAND[0] - 7
    d.text((MARGIN_X, y), "redaction-pack", font=title_f, fill=TEXT)
    y += 74
    d.text((MARGIN_X, y), f"{len(pack.patterns.FORMATS)} more credential formats for Hermes's secret redactor",
           font=sub_f, fill=MUTED)
    y += 50

    panel_top, line_h, pad = y, 30, 18
    panel_bottom = panel_top + pad * 2 + line_h * len(pairs) * 2 - 6
    d.rounded_rectangle((MARGIN_X - 4, panel_top, W - MARGIN_X + 4, panel_bottom), radius=12,
                        fill=PANEL, outline=PANEL_EDGE, width=2)
    text_w = W - 2 * MARGIN_X - 2 * pad - 30
    ty = panel_top + pad
    for before, after in pairs:
        d.text((MARGIN_X + pad, ty), "-", font=code_f, fill=LEAK)
        d.text((MARGIN_X + pad + 30, ty), clip(d, before, code_f, text_w), font=code_f, fill=LEAK)
        ty += line_h
        d.text((MARGIN_X + pad, ty), "+", font=code_f, fill=SAFE)
        d.text((MARGIN_X + pad + 30, ty), clip(d, after, code_f, text_w), font=code_f, fill=TEXT)
        ty += line_h

    left, top, right, bottom = ink.getbbox()
    assert BAND[0] <= top and bottom <= BAND[1], f"ink rows {top}-{bottom} outside {BAND}"
    assert 0 < left and right < W, f"ink columns {left}-{right} outside the card"

    card = Image.new("RGBA", (W, H), BG + (255,))
    card.alpha_composite(ink)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    card.convert("RGB").save(args.out, optimize=True)
    print(f"{args.out} ink rows {top}-{bottom}, columns {left}-{right}")
    for before, after in pairs:
        print(f"  {after}")


if __name__ == "__main__":
    main()

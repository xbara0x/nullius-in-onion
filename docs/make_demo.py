#!/usr/bin/env python3
"""Render a terminal transcript as an animated SVG and a GIF.

Used to produce docs/demo.svg and docs/demo.gif from a real run:

    python3 onion_status_check.py examples/targets.txt --indices examples/indices.txt 2>&1 \
        | sed "s#$PWD/results/#results/#g" > docs/transcript.txt
    python3 docs/make_demo.py docs/transcript.txt docs/demo

Lines appear one after another; lines that start with '[' (per-target
progress) get a shorter pause than summary lines so the whole thing stays
around 20 s. No dependency beyond Pillow for the GIF.
"""

from __future__ import annotations

import html
import re
import sys
from pathlib import Path

PROMPT = "$ python3 onion_status_check.py examples/targets.txt --indices examples/indices.txt"
COLS, FONT_PX, LINE_H, PAD = 100, 14, 22, 18
BG, FG, DIM, GREEN, YELLOW, BLUE, RED = "#0d1117", "#d0d7de", "#8b949e", "#3fb950", "#d29922", "#58a6ff", "#f85149"


def color_for(line: str) -> str:
    s = line.strip()
    if s.startswith("$ "):
        return FG
    if s.startswith("Done:") or s.startswith("Controls: 3/3") or s.startswith("Indices:"):
        return GREEN
    if s.startswith("caveat:") or "WARNING" in s or "FAILED" in s:
        return YELLOW
    if s.startswith("listed:") or s.startswith("name-match:"):
        return BLUE
    if s.startswith("[") or s.startswith("Loading") or s.startswith("Checking") or s.startswith("Measuring"):
        return DIM
    if s.startswith("JSON:") or s.startswith("HTML:") or s.startswith("Controls: results"):
        return DIM
    return FG


def delay_for(line: str) -> float:
    s = line.strip()
    if not s:
        return 0.3
    if s.startswith("["):
        return 1.2  # a real request takes seconds; hint at it without waiting
    if s.startswith("$ "):
        return 1.0
    return 0.45


def load(path: Path) -> list[str]:
    lines = [PROMPT] + path.read_text(encoding="utf-8").rstrip("\n").split("\n")
    return [l[:COLS] for l in lines]


def write_svg(lines: list[str], out: Path) -> None:
    w = PAD * 2 + int(COLS * FONT_PX * 0.602)
    h = PAD * 2 + LINE_H * len(lines) + 24
    t = 0.0
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}" font-family="DejaVu Sans Mono, JetBrains Mono, Menlo, Consolas, monospace" font-size="{FONT_PX}">',
             f'<rect width="100%" height="100%" rx="8" fill="{BG}"/>',
             '<circle cx="22" cy="18" r="5" fill="#ff5f56"/><circle cx="40" cy="18" r="5" fill="#ffbd2e"/><circle cx="58" cy="18" r="5" fill="#27c93f"/>',
             '<style>.l{opacity:0;animation:show .01s linear forwards}@keyframes show{to{opacity:1}}'
             '.c{animation:blink 1s steps(1) infinite}@keyframes blink{50%{opacity:0}}</style>']
    y = PAD + 24
    for i, line in enumerate(lines):
        parts.append(f'<text class="l" x="{PAD}" y="{y + LINE_H * i}" fill="{color_for(line)}" '
                     f'style="animation-delay:{t:.2f}s" xml:space="preserve">{html.escape(line)}</text>')
        t += delay_for(line)
    parts.append(f'<rect class="c" x="{PAD}" y="{y + LINE_H * len(lines) - FONT_PX}" width="{int(FONT_PX*0.6)}" height="{FONT_PX + 2}" fill="{FG}"/>')
    parts.append("</svg>")
    out.write_text("\n".join(parts), encoding="utf-8")


def write_gif(lines: list[str], out: Path) -> None:
    from PIL import Image, ImageDraw, ImageFont
    font = None
    for cand in ("/usr/share/fonts/TTF/DejaVuSansMono.ttf", "/usr/share/fonts/TTF/JetBrainsMonoNerdFontMono-Regular.ttf",
                 "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"):
        if Path(cand).exists():
            font = ImageFont.truetype(cand, FONT_PX)
            break
    if font is None:
        font = ImageFont.load_default()
    cw = font.getlength("M")
    w = int(PAD * 2 + COLS * cw)
    h = PAD * 2 + LINE_H * len(lines) + 24
    frames, durations = [], []
    for n in range(1, len(lines) + 1):
        img = Image.new("RGB", (w, h), BG)
        d = ImageDraw.Draw(img)
        for cx, col in ((22, "#ff5f56"), (40, "#ffbd2e"), (58, "#27c93f")):
            d.ellipse((cx - 5, 13, cx + 5, 23), fill=col)
        y = PAD + 24
        for i in range(n):
            d.text((PAD, y + LINE_H * i - FONT_PX), lines[i], font=font, fill=color_for(lines[i]))
        d.rectangle((PAD, y + LINE_H * n - FONT_PX, PAD + int(cw), y + LINE_H * n + 2), fill=FG)
        frames.append(img)
        durations.append(int(delay_for(lines[n - 1]) * 1000))
    durations[-1] = 4000  # hold the final frame
    frames[0].save(out, save_all=True, append_images=frames[1:], duration=durations, loop=0, optimize=True)


def main() -> None:
    if len(sys.argv) != 3:
        sys.exit("usage: make_demo.py transcript.txt out-basename")
    lines = load(Path(sys.argv[1]))
    base = Path(sys.argv[2])
    write_svg(lines, base.with_suffix(".svg"))
    write_gif(lines, base.with_suffix(".gif"))
    print(f"{base.with_suffix('.svg')}  {base.with_suffix('.gif')}  ({len(lines)} lines)")


if __name__ == "__main__":
    main()

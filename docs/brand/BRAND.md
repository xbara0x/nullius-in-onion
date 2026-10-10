# Nullius in Onion: brand notes

## The idea in one line

*Nullius in verba*, "take nobody's word": an onion cut open and drawn like a copperplate figure,
half skin and half section, seen through a lens. Don't trust the skin, look inside.

The drawing is an original work in the manner of the engraved plates of Robert Hooke's
*Micrographia* (London, 1665), the book of the Royal Society's first great microscope
observations; the book is in the public domain and no plate of it is reproduced here. The lettered
figures **A** (the skin: what an address claims) and **B** (the scales: what is inside) and the
caption *Fig. I.* are a nod to that book. This is an independent project, not affiliated with or
endorsed by the Royal Society or the Tor Project; the artwork is drawn so that nobody could take
it for either's. "Tor" is used in words only, to say what the tool reaches.

## The files and when to use each

| File | Use |
|---|---|
| `emblem.svg`, `emblem-dark.svg` | The full roundel (ring lettering reads NULLIUS IN ONION / TAKE NOBODY'S WORD). Where there is room to be looked at: stickers, posters, a documentation title page, a conference slide of its own. **192 px and up.** |
| `plate.svg`, `plate-dark.svg` | The same lens without the ring lettering, labels or ornaments. Use it wherever the name already appears next to it (avatars, a slide corner, a social card) and **wherever a roundel could be mistaken for an institutional seal.** 64 px and up. |
| `lockup.svg`, `lockup-dark.svg` | README header: plate, the name, the motto line. Made for about 130 px tall; the snippet below uses width 640 (132 px tall). Not below 96 px tall. |
| `icon.svg`, `icon-dark.svg` | The small mark, 24 to 48 px (up to 64): favicon-size and list-icon-size uses. Same onion as the emblem with the linework thinned for pixels. Do not enlarge it past 64 px; use the plate. |
| `icon-16.svg`, `icon-16-dark.svg` | The 16 px cut, drawn on the pixel grid. Use it at 16 px (or 32 px, a whole multiple). |
| `favicon.ico` | 16, 32 and 48 px inside, rendered from the icon cuts. |
| `social-preview.png` | 1280 x 640 card for the repository's social preview (under 1 MB, GitHub's limit). |

The `-dark` files are the same artwork with a lifted bezel (so the edge does not sink into a dark
page). Every SVG has an intrinsic size and a `viewBox`, so it scales to anything; for a PNG,
render the SVG at the size you need (for example `rsvg-convert -w 1024 emblem.svg -o emblem.png`).

The README header is:

```html
<h1 align="center"><picture><source media="(prefers-color-scheme: dark)" srcset="docs/brand/lockup-dark.svg"><img src="docs/brand/lockup.svg" alt="Nullius in Onion" width="640"></picture></h1>
```

## Colours

Contrast ratios are against `#ffffff` / `#0d1117` (GitHub's light and dark pages), given for the
colours that carry text; the two colours that live only on the parchment social card are given
against the card (`#f1e6c6`) instead.

| Hex | Name | Role | Contrast |
|---|---|---|---|
| `#2a1b10` | ink | linework, bezel, wordmark on light backgrounds | 16.63 / 1.14 |
| `#f3e8cb` | parchment | ring lettering, wordmark and motto line on dark backgrounds | 1.22 / 15.51 |
| `#ecdfbc` | field | the lens field (the parchment of the lens itself) | decorative |
| `#fffef3` | cut white | the palest tone of the cut half (the luminous section) | decorative |
| `#bc7b00` | amber | the skin; the word *in* on white (large text only) | 3.52 / 5.38 |
| `#d29922` | amber, lit | the bezel hairline (light files); *in* and the motto on dark | 2.52 / 7.50 |
| `#edc05a` | amber, highlight | the bezel hairline in the dark files | decorative |
| `#8a5709` | shadow amber | skin shadow; the motto line on light | 6.09 / 3.11 |
| `#a86f00` | deep amber | *in* and the rule on the parchment social card (large text) | 3.42 on the card |
| `#6b4106` | caption brown | the URL line on the social card | 7.08 on the card |
| `#9a5a17` | russet | dry skin, fine lines (decorative) | decorative |
| `#7a4710` | plate | the basal plate (decorative) | decorative |
| `#4e2d0d` | deep | the core shadow of the skin (decorative) | decorative |
| `#34220f` | dark bezel | the bezel of the *-dark* files (decorative) | decorative |
| `#aab36e` | sage | the youngest leaves inside the cut (decorative, never bright) | decorative |

The table lists the main colours. The engraving also uses intermediate tints between them (the cut
half steps from dry amber to cream, the skin has three tonal steps), all inside the same
ink / amber / cream family. Purple never appears, and nothing is green except the muted sage of the
youngest leaves inside the cut.

## Typography

Noto Serif Display (SIL Open Font License 1.1): Bold for the name and the ring capitals (tracked
0.24 em), Bold Italic for *in*, Bold capitals for the motto line (0.20 em), Italic for the
figure labels and the tagline. The URL line of the social card is JetBrains Mono (OFL). **All type
in the SVG files is outlined**: the fonts are not needed to display them, and the files contain no
`<text>`.

## Clear space and minimum sizes

* Clear space: one eighth of the lens diameter on every side of the emblem, the plate and the
  lens of the lockup. Nothing else (text, edges) enters it.
* Minimum sizes: emblem 192 px; plate 64 px; lockup 96 px tall; icon 24 px; the 16 px cut at
  16 px. Below 192 px the emblem's lettering turns into a dotted rim (it is legible from about
  160 px and mush at 128): use the plate or the icon instead.
* Backgrounds: the artwork carries its own parchment lens and ink bezel, so it sits on white,
  on `#0d1117` and on quiet mid-tones alike. Keep it off photographs and busy patterns.

## Don'ts

* No purple, no Tor-style concentric onion, no bright green sprout: that palette belongs to the
  Tor Project. Never put the Tor Project's onion logo or the Tor Browser icon next to, inside or
  in imitation of this mark (not in a lockup, a banner, a social card or a mock-up); mention Tor
  in words only. No purple variant or purple dark-mode accent, either.
* Do not recolour the engraving (no monochrome tint, no gradient map, no neon): the ink-and-amber
  palette is part of the idea. A one-colour version, if ever needed, is a new drawing, not a filter.
* Do not add shields, crowns, laurels, banners, stars, dates, maces or "society"-style text (and
  never the Royal Society's arms or name in the artwork), and do not change the ring lettering.
* Do not stretch, skew, rotate, outline, shadow or glow it; do not crop the lens.
* Do not put the roundel where it could pass for an official seal: certificates, signed
  statements, "verified" or "certified" badges, anything that implies an institution stands behind a
  result. Use the plate there, or no mark at all.
* Do not use the icon above 64 px or the emblem below 192 px.
* Do not redraw the onion to look more like garlic, or more like a flame.

These files are part of Nullius in Onion and are released under its [MIT License](../../LICENSE).

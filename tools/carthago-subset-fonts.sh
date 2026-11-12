#!/usr/bin/env bash
# Regenerates the dashboard's self-hosted fonts in backend/internal/dashboard/static/fonts
# from the upstream releases, pinned by SHA-256:
#   Inter 4.1            https://github.com/rsms/inter            (SIL Open Font License 1.1)
#   JetBrains Mono 2.304 https://github.com/JetBrains/JetBrainsMono (SIL Open Font License 1.1)
# Neither licence declares a Reserved Font Name, so the subsets keep the family names.
#
# Inter: the variable font with the optical size fixed at 14 and the weight axis cut to
# 400-600. JetBrains Mono: the hinted Regular. Both are cut to Basic Latin, Latin-1 and the
# punctuation, arrows and maths signs the dashboard prints; contextual alternates and coding
# ligatures are dropped so identifiers such as 0x1f00000 are never reshaped.
# Needs curl, unzip and python3 with fonttools and brotli (pip install fonttools brotli).
# Usage: tools/carthago-subset-fonts.sh
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
out="$root/backend/internal/dashboard/static/fonts"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

fetch() { # url sha256 file
    curl -fsSL -o "$work/$3" "$1"
    echo "$2  $work/$3" | sha256sum -c --quiet -
}
fetch https://github.com/rsms/inter/releases/download/v4.1/Inter-4.1.zip \
    9883fdd4a49d4fb66bd8177ba6625ef9a64aa45899767dde3d36aa425756b11e inter.zip
fetch https://github.com/JetBrains/JetBrainsMono/releases/download/v2.304/JetBrainsMono-2.304.zip \
    6f6376c6ed2960ea8a963cd7387ec9d76e3f629125bc33d1fdcd7eb7012f7bbf jbm.zip
unzip -q "$work/inter.zip" InterVariable.ttf LICENSE.txt -d "$work/inter"
unzip -q "$work/jbm.zip" fonts/ttf/JetBrainsMono-Regular.ttf OFL.txt -d "$work/jbm"

unicodes="U+0020-007E,U+00A0-00FF,U+0131,U+0152-0153,U+02C6,U+02DC,U+0394,U+03A3,U+03BC"
unicodes+=",U+2010-2015,U+2018-201A,U+201C-201E,U+2020-2022,U+2026,U+2030,U+2032-2033"
unicodes+=",U+2039-203A,U+2044,U+20AC,U+2122,U+2190-2193,U+2212,U+221A,U+221E,U+2248,U+2260"
unicodes+=",U+2264-2265"
names="0,1,2,3,4,5,6,13,14" # keeps the copyright and licence records inside the files

python3 -m fontTools varLib.instancer "$work/inter/InterVariable.ttf" opsz=14 wght=400:600 \
    --no-recalc-timestamp -q -o "$work/inter-text.ttf"
python3 -m fontTools subset "$work/inter-text.ttf" --unicodes="$unicodes" \
    --layout-features=kern,tnum,ccmp,locl,mark,mkmk --name-IDs="$names" \
    --no-recalc-timestamp --flavor=woff2 --output-file="$out/inter-latin.woff2"
python3 -m fontTools subset "$work/jbm/fonts/ttf/JetBrainsMono-Regular.ttf" --unicodes="$unicodes" \
    --layout-features=kern,ccmp,locl,mark,mkmk --name-IDs="$names" \
    --no-recalc-timestamp --flavor=woff2 --output-file="$out/jetbrains-mono-latin.woff2"
cp "$work/inter/LICENSE.txt" "$out/inter-LICENSE.txt"
cp "$work/jbm/OFL.txt" "$out/jetbrains-mono-LICENSE.txt"
wc -c "$out"/*.woff2

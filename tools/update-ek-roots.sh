#!/usr/bin/env bash
# Regenerates backend/internal/attest/ekroots/certs/*.pem from Microsoft's TrustedTpm.cab,
# the TPM vendor root and intermediate CA bundle Windows uses for EK validation.
# Needs curl, cabextract and openssl. Usage: tools/update-ek-roots.sh [path/to/TrustedTpm.cab]
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
out="$root/backend/internal/attest/ekroots/certs"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

cab=${1:-}
if [ -z "$cab" ]; then
    cab="$work/TrustedTpm.cab"
    curl -fsSL -o "$cab" "https://go.microsoft.com/fwlink/?linkid=2097925"
fi
mkdir -p "$work/x"
cabextract -q -d "$work/x" "$cab" 2>/dev/null || true

# Vendor directory in the cab -> bundle file prefix.
vendors="AMD:amd Infineon:infineon Intel:intel Nuvoton:nuvoton STMicro:stmicro"

mkdir -p "$out"
rm -f "$out"/*.pem
for pair in $vendors; do
    dir=${pair%%:*}
    name=${pair##*:}
    for kind in RootCA:roots IntermediateCA:intermediates; do
        src="$work/x/$dir/${kind%%:*}"
        dst="$out/$name-${kind##*:}.pem"
        : > "$dst"
        find "$src" -maxdepth 1 -type f \( -iname '*.cer' -o -iname '*.crt' -o -iname '*.der' -o -iname '*.pem' \) -print0 | sort -z |
            while IFS= read -r -d '' f; do
                pem=$(openssl x509 -inform DER -in "$f" 2>/dev/null || openssl x509 -inform PEM -in "$f" 2>/dev/null || true)
                if [ -z "$pem" ] && openssl asn1parse -inform DER -in "$f" >/dev/null 2>&1; then
                    # Some vendor CAs (STMicro) have a non-minimal serial INTEGER that strict
                    # parsers reject; keep the exact DER, the Go loader parses it leniently.
                    pem=$(printf -- '-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----' "$(base64 -w 64 < "$f")")
                    echo "kept raw DER (strict parse fails): $dir/${kind%%:*}/$(basename "$f")" >&2
                fi
                if [ -z "$pem" ]; then
                    echo "skip (unparseable): $dir/${kind%%:*}/$(basename "$f")" >&2
                    continue
                fi
                printf '# %s\n%s\n' "$(basename "$f")" "$pem" >> "$dst"
            done
    done
done
# AMD's fTPM intermediates chain to two self-signed "AMDTPM" roots that TrustedTpm.cab does
# not ship. Fetch them from AMD's AIA service and pin their SHA-256 fingerprints.
amd_roots="264D39A23CEB5D5B49D610044EEBD121:67BD2472A546751CACA5F358A78F80727531671338960A9BCFDFBE6A34D0C6A1
23452201D41C5AB064032BD23F158FEF:14AAC9FD58471A612AFD75D8C0955DAF99F091B1863702F9E0D4113FAF234F9D"
for pair in $amd_roots; do
    id=${pair%%:*}
    want=${pair##*:}
    f="$work/amd-$id.cer"
    curl -fsSL -o "$f" "https://ftpm.amd.com/pki/aia/$id"
    got=$(openssl x509 -inform DER -in "$f" -noout -fingerprint -sha256 | cut -d= -f2 | tr -d ':')
    if [ "$got" != "$want" ]; then
        echo "AMD root $id fingerprint $got, want $want" >&2
        exit 1
    fi
    printf '# AMDTPM root (https://ftpm.amd.com/pki/aia/%s)\n%s\n' "$id" "$(openssl x509 -inform DER -in "$f")" >> "$out/amd-roots.pem"
done

head -n 2 "$work/x/version.txt" | tail -n 1 | sed 's/^/TrustedTpm.cab: /' > "$out/VERSION"
echo "wrote $(grep -c 'BEGIN CERTIFICATE' "$out"/*.pem | awk -F: '{s+=$2} END {print s}') certificates to $out"

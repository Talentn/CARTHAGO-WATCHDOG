#!/usr/bin/env bash
# Regenerates backend/internal/attest/ekroots/certs/*.pem from Microsoft's TrustedTpm.cab,
# the TPM vendor root and intermediate CA bundle Windows uses for EK validation.
# AMD and Intel CAs the cab lacks are fetched from the vendors and pinned by SHA-256.
# Needs curl, cabextract and openssl. Usage: tools/carthago-update-ek-roots.sh [path/to/TrustedTpm.cab]
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

# Intel On-Die CA (ODCA) certificates published on tsci.intel.com, pinned by SHA-256.
# Intel PTT EKs (11th gen Core and later) chain EK -> "CSME <platform> PTT 01SVN" ->
# "CSME <platform> SVN01 Kernel CA" -> "CSME <platform> ROM CA" -> an On-Die issuing CA
# below. The first three are unique to each device and only exist in the TPM's EK
# certificate chain NV indices, which the client sends; the issuing CAs are public.
# TrustedTpm.cab omits some of them (T_TGL, E_TGL), so add any it does not already carry.
intel_odca="OnDie_CA_CSME_Intermediate:5E3EEE5748AC13E0B3D1227FCDC4751AA1402DDE8031D21F63CB4ECF43F02440
ODCA_CA2_CSME_Intermediate:C001DF02B31A60A2B37130365956400A2AFCFD147E8552FD7EA3F17F2AB0D457
ODCA_CA2_OSSE_Intermediate:98F575D37FCCE1139BA4DDFBA811D862A8262A207CB46F4C8BD0D9891E406475
MCC_00001881_OnDie_CA:D4A82DDE06A12689AE22A50870003DE03AC04205E921410C60EB0216FB15BAFF
EBG_00002001_OnDie_CA:342FAF1D78D3473E0813617CF62E0353FCCAEF85FFFF0E5E64D2DBF3053A4545
TGL_00002002_OnDie_CA:17E1688F0246909E16C4FD0A673B30ACD83732DD98FBF67D703536A84E7AC6EC
TGL_00002003_OnDie_CA:27904BFD7A64112FDA1162FA6112DA0D44B4E4A1C4A51B7A351F9973DDC6EBF3
TGL_00002004_OnDie_CA:D57E560FBC4BC5708F7204E2C1761E33B488590EE0FC11E1CB63593C4B645AC2
ADL_00002226_ODCA_CA2:8C1B4D34DFC2DF3386A0F0EC7747FDE7BAC6B6C9EB1EE1F7966B9C8D663C26B3
ADL_00002701_ODCA_CA2:71838FB00163F14399B6469F64790F7ACEEC82DF08B0268213E2C1E2BD0599AB"
intel_root=BEB40BB7507B33967226AA80E084749FBB6593893C642E818D682E9A8D07FC24
fingerprints() {
    awk -v d="$work/split" 'BEGIN{system("mkdir -p " d)} /BEGIN CERT/{n++; f=d "/" n ".pem"} f{print > f} /END CERT/{close(f); f=""}' "$@"
    for c in "$work"/split/*.pem; do openssl x509 -in "$c" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2 | tr -d ':'; done
    rm -rf "$work/split"
}
have=$(fingerprints "$out/intel-roots.pem" "$out/intel-intermediates.pem")
if ! grep -qx "$intel_root" <<<"$have"; then
    echo "Intel OnDie CA root $intel_root missing from TrustedTpm.cab" >&2
    exit 1
fi
for pair in $intel_odca; do
    name=${pair%%:*}
    want=${pair##*:}
    f="$work/intel-$name.cer"
    curl -fsSL -o "$f" "https://tsci.intel.com/content/OnDieCA/certs/$name.cer"
    got=$(openssl x509 -inform DER -in "$f" -noout -fingerprint -sha256 | cut -d= -f2 | tr -d ':')
    if [ "$got" != "$want" ]; then
        echo "Intel ODCA $name fingerprint $got, want $want" >&2
        exit 1
    fi
    if ! grep -qx "$want" <<<"$have"; then
        printf '# Intel ODCA (https://tsci.intel.com/content/OnDieCA/certs/%s.cer)\n%s\n' "$name" "$(openssl x509 -inform DER -in "$f")" >> "$out/intel-intermediates.pem"
    fi
done

head -n 2 "$work/x/version.txt" | tail -n 1 | sed 's/^/TrustedTpm.cab: /' > "$out/VERSION"
echo "wrote $(grep -c 'BEGIN CERTIFICATE' "$out"/*.pem | awk -F: '{s+=$2} END {print s}') certificates to $out"

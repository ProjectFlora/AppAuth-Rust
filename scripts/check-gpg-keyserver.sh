#!/usr/bin/env bash
# Verifies that the public part of the release signing key resolves at the
# key server before any release package is built.
#
# Maven Central's sync validation fetches the signing key's public key from
# a key server; v0.6.0's upload was rejected because the freshly created key
# was not there yet (#131). This check fails the run, before any build job
# starts, if the public key is not resolvable by fingerprint.
#
# It covers every *primary* key in GPG_PRIVATE_KEY, whether the secret holds
# a secret key block (a GPG_PRIVATE_KEY secret almost always does) or a public
# key block. A secret key packet (type 5) embeds the full public key packet
# (RFC 9580 section 5.5.3), and a version 4 fingerprint is computed over that
# public part only, so the parser recovers the public part from the secret
# packet and fingerprints it. A key server lookup by primary fingerprint
# returns the whole key block, subkeys included, and keys.openpgp.org does
# not resolve subkey fingerprints on the by-fingerprint endpoint, so subkeys
# are deliberately not checked.
#
# A primary key that cannot be fingerprinted (an unsupported key version, or
# a secret packet whose fields do not parse) fails the gate rather than being
# skipped: its publication cannot be verified, so it must not let the run
# through on the strength of another key in the same secret.
#
# GPG_PRIVATE_KEY is required. This differs from
# check-android-maven-publication.sh, which skips its signature checks when
# the signing key is unset: this check runs on every release dispatch
# (candidate and publish), and a missing secret would break the Maven
# Central publication, so it fails loudly instead of skipping.
#
# The key material is never echoed; only fingerprints are.
#
# Environment:
#   GPG_PRIVATE_KEY        the ASCII-armored private signing key (required);
#                          one or more keys, or a single raw base64 key
#   KEYSERVER_BASE_URL     default https://keys.openpgp.org
#   KEYSERVER_ATTEMPTS     total attempts per key, default 3
#   KEYSERVER_RETRY_DELAY  seconds between attempts, default 30
#   KEYSERVER_TIMEOUT      per-request timeout in seconds, default 30

set -euo pipefail

if [[ $# -ne 0 ]]; then
    echo "Usage: $0" >&2
    echo "The signing key is taken from the GPG_PRIVATE_KEY environment variable." >&2
    exit 2
fi

KEYSERVER_BASE_URL="${KEYSERVER_BASE_URL:-https://keys.openpgp.org}"
KEYSERVER_ATTEMPTS="${KEYSERVER_ATTEMPTS:-3}"
KEYSERVER_RETRY_DELAY="${KEYSERVER_RETRY_DELAY:-30}"
KEYSERVER_TIMEOUT="${KEYSERVER_TIMEOUT:-30}"

for value in "$KEYSERVER_ATTEMPTS" "$KEYSERVER_RETRY_DELAY" "$KEYSERVER_TIMEOUT"; do
    if [[ ! "$value" =~ ^[0-9]+$ ]]; then
        echo "KEYSERVER_ATTEMPTS, KEYSERVER_RETRY_DELAY and KEYSERVER_TIMEOUT must be non-negative integers" >&2
        exit 2
    fi
done

if [[ -z "${GPG_PRIVATE_KEY:-}" ]]; then
    cat >&2 <<'EOF'
GPG_PRIVATE_KEY is not set.

This check verifies that the release signing key's public key is resolvable
at the key server; Maven Central's sync validation fetches it from there,
and its absence rejected v0.6.0's upload (#131). The Release workflow
injects the repository secret of the same name.

Set the GPG_PRIVATE_KEY repository secret to the ASCII-armored private key
and re-dispatch the run.
EOF
    exit 1
fi

workdir=$(mktemp -d)
trap 'rm -rf "$workdir"' EXIT
key_file="$workdir/key"
printf '%s\n' "$GPG_PRIVATE_KEY" > "$key_file"
chmod 600 "$key_file"

# The parser is standard-library Python so the check runs on any machine
# with python3 (no GnuPG dependency). Fingerprint: RFC 9580 section 5.5.4.2
# (v4: SHA-1 of 0x99 + 2-octet body length + body). A secret key packet
# (type 5) embeds the public key packet, so its public part is recovered by
# parsing the algorithm-specific material (section 5.5.5) and validating the
# secret tail (section 5.5.3); the fingerprint then uses that public part.
cat > "$workdir/parse_key.py" <<'PY'
import base64
import binascii
import hashlib
import re
import sys

B64 = re.compile(r"[A-Za-z0-9+/=]+$")
# Non-greedy: a file may hold several blocks (a secret with multiple keys).
ARMOR = re.compile(
    r"-----BEGIN PGP (?:PUBLIC|SECRET|PRIVATE) KEY BLOCK-----(.*?)\n"
    r"-----END PGP (?:PUBLIC|SECRET|PRIVATE) KEY BLOCK-----",
    re.S)


def fail(message):
    print("check-gpg-keyserver: %s" % message, file=sys.stderr)
    sys.exit(1)


def crc24(data):
    crc = 0xB704CE
    for byte in data:
        crc ^= byte << 16
        for _ in range(8):
            crc <<= 1
            if crc & 0x1000000:
                crc &= 0x00FFFFFF
                crc ^= 0x864CFB
    return crc & 0xFFFFFF


def pad(s):
    s = s.rstrip("=")
    return s + "=" * (-len(s) % 4)


def _decode_lines(lines):
    try:
        return base64.b64decode(pad("".join(lines)), validate=True)
    except (binascii.Error, ValueError):
        return None


def _looks_like_footer(line):
    # RFC 9580 section 6.1: '=' + 4 base64 chars; the RFC 4880 form is
    # 4 chars + '=='. Real data lines end at a 4-char boundary, so a short
    # final line of this shape is a footer (when it is not, the fallback
    # below decodes every line as payload).
    if line.startswith("="):
        return len(line) <= 6
    return len(line) == 6 and line.endswith("==")


def _check_footer(data, footer):
    # RFC 9580 section 6.1: the footer is optional and a missing or
    # disagreeing one MUST NOT reject the object, so this only warns.
    # The packet parse (and, for key server responses, the key server's
    # own data) is the real validation.
    try:
        crc = base64.b64decode(pad(footer.lstrip("=")), validate=True)
    except (binascii.Error, ValueError):
        print("note: the armor CRC24 footer is malformed; continuing anyway", file=sys.stderr)
        return
    if len(crc) != 3 or crc24(data) != int.from_bytes(crc, "big"):
        print("note: the armor CRC24 footer does not match the data; continuing anyway "
              "(RFC 9580 section 6.1: a mismatched footer must not reject a key)", file=sys.stderr)


def decode_block(text):
    """Decode one armored block (or a raw base64 blob) to bytes.

    Returns None when the base64 payload cannot be recovered.
    """
    lines = [line.strip() for line in text.splitlines()
             if line.strip() and B64.fullmatch(line.strip())]
    if not lines:
        return None
    if len(lines) >= 2 and _looks_like_footer(lines[-1]):
        payload_lines = lines[:-1]
    else:
        payload_lines = lines
    data = _decode_lines(payload_lines)
    if data is None and len(payload_lines) != len(lines):
        # The "footer" did not yield a decodable payload; it may have been
        # a short final data line instead.
        data = _decode_lines(lines)
    if data is None:
        return None
    if len(payload_lines) != len(lines):
        _check_footer(data, lines[-1])
    return data


def key_blocks(text):
    blocks = ARMOR.findall(text)
    if blocks:
        return blocks
    stripped = "".join(text.split())
    if stripped and B64.fullmatch(stripped):
        return [text]
    return []


def iter_packets(data):
    """Yield (tag, body) for each OpenPGP packet (RFC 9580 section 4.2)."""
    i = 0
    n = len(data)
    while i < n:
        first = data[i]
        if not (first & 0x80):
            i += 1
            continue
        if first & 0x40:
            # New form: tag is bits 5..0, then the new partial/full length.
            tag = first & 0x3F
            i += 1
            if i >= n:
                return
            l0 = data[i]
            if l0 < 192:
                length = l0
                i += 1
            elif l0 < 224:
                if i + 1 >= n:
                    return
                length = ((l0 - 192) << 8) + data[i + 1] + 192
                i += 2
            elif l0 == 255:
                if i + 4 > n:
                    return
                length = int.from_bytes(data[i + 1:i + 5], "big")
                i += 5
            else:
                length = 0
                while i < n:
                    l = data[i]
                    if 224 <= l < 255:
                        length += 1 << (l & 0x1F)
                        i += 1
                    elif l < 192:
                        length += l
                        i += 1
                        break
                    elif l < 224:
                        if i + 1 >= n:
                            return
                        length += ((l - 192) << 8) + data[i + 1] + 192
                        i += 2
                        break
                    else:
                        if i + 4 > n:
                            return
                        length += int.from_bytes(data[i + 1:i + 5], "big")
                        i += 5
                        break
        else:
            # Legacy form: tag is bits 5..2, length type is bits 1..0.
            tag = (first >> 2) & 0x0F
            length_type = first & 0x03
            if length_type == 0:
                length = data[i + 1]
                i += 2
            elif length_type == 1:
                length = int.from_bytes(data[i + 1:i + 3], "big")
                i += 3
            elif length_type == 2:
                length = int.from_bytes(data[i + 1:i + 5], "big")
                i += 5
            else:
                length = n - i - 1
                i += 1
        if i + length > n:
            if tag in (5, 6):
                fail("a primary key packet is truncated; check the secret for corruption")
            return
        yield tag, data[i:i + length]
        i += length


def fingerprint_v4(body):
    return hashlib.sha1(b"\x99" + len(body).to_bytes(2, "big") + body).hexdigest().upper()


# Symmetric ciphers and their block sizes in octets (RFC 9580 section 9.3).
# The block size is the size of the IV in a passphrase-protected secret
# key packet.
CIPHER_BLOCK_SIZES = {
    1: 8,    # IDEA
    2: 8,    # TripleDES
    3: 8,    # CAST5
    4: 8,    # Blowfish
    7: 16,   # AES-128
    8: 16,   # AES-192
    9: 16,   # AES-256
    10: 16,  # Twofish
    11: 16,  # Camellia-128
    12: 16,  # Camellia-192
    13: 16,  # Camellia-256
}

# Size in octets of the type-specific fields of an S2K specifier, not
# counting the 1-octet S2K type (RFC 9580 section 3.7.1).
S2K_FIELD_SIZES = {
    0: 1,    # simple: 1-octet hash algorithm
    1: 8,    # salted: 8-octet salt
    3: 9,    # iterated and salted: 8-octet salt + 1-octet count code
}


def _mpi_end(data, i):
    """Return the index just past the MPI (RFC 9580 section 3.2) at data[i],
    or None when it is truncated. The 2-octet length is in bits; a
    non-minimal encoding (leading octet with a clear top bit) is tolerated
    because the section 3.2 minimal rule is a version 6 MUST only."""
    if i + 2 > len(data):
        return None
    bits = int.from_bytes(data[i:i + 2], "big")
    if bits == 0:
        return i + 2
    end = i + 2 + (bits + 7) // 8
    return end if end <= len(data) else None


def _mpi_run(data):
    """Count the consecutive MPIs spanning data exactly; None when any MPI is
    truncated. An MPI's bit count bounds its content, so a random octet
    stream usually fails this walk: a passing run is a strong structural
    signal that the octets really are secret key material."""
    count = 0
    i = 0
    while i < len(data):
        end = _mpi_end(data, i)
        if end is None:
            return None
        i = end
        count += 1
        if count > 256:
            return None
    return count


def _public_material_end(body):
    """Locate the end of the algorithm-specific public key material of a
    version 4 key packet body (RFC 9580 sections 5.5.2.2 and 5.5.5).
    Returns the index in the body just past the material, or None when the
    material cannot be parsed (unknown algorithm, or an MPI whose declared
    bit count overruns the packet). In a secret key packet that index is
    where the S2K usage octet begins (section 5.5.3) and the tail is
    validated separately, so the material itself need not run to the end of
    the body; a public key packet's material does."""
    if len(body) < 7 or body[0] != 4:
        return None
    algo = body[5]
    mat = body[6:]
    if algo in (1, 2, 3):  # RSA: modulus, public exponent (5.5.5.2)
        end = _mpi_end(mat, 0)
        end = _mpi_end(mat, end) if end is not None else None
    elif algo in (16, 17):  # ElGamal (16) / DSA (17): p, q, g, y
        end = 0
        for _ in range(4):
            end = _mpi_end(mat, end)
            if end is None:
                break
    elif algo in (18, 19):  # ECDH / ECDSA: [1-octet len][curve OID][point MPI]
        if mat[0] in (0, 0xFF):  # reserved variable-length values
            return None
        end = 1 + mat[0]
        end = _mpi_end(mat, end) if end <= len(mat) else None
        if end is not None and algo == 18:  # ECDH appends [1-octet len][KDF]
            if end + 1 > len(mat) or mat[end] in (0, 0xFF):
                end = None
            else:
                end += 1 + mat[end]
                if end > len(mat):
                    end = None
    elif algo == 22:  # EdDSA: [1-octet len][curve OID][MPI: format + key]
        if mat[0] in (0, 0xFF):
            return None
        end = 1 + mat[0]
        if end + 2 > len(mat):
            end = None
        else:
            bits = int.from_bytes(mat[end:end + 2], "big")
            octets = (bits + 7) // 8 if bits else 0
            if octets < 2:  # a point is at least a format + 1 key octet
                end = None
            else:
                end += 2 + octets
                if end > len(mat):
                    end = None
    else:
        return None  # unknown or reserved public key algorithm
    if end is None or end <= 0 or end >= len(mat):
        # The material is empty, or ran all the way to the end of the body:
        # a secret key packet must have a non-empty tail after it.
        return None
    return 6 + end


def _secret_tail_ok(body, b):
    """Check the secret key fields (RFC 9580 section 5.5.3) of a version 4
    secret key packet from body[b], the S2K usage octet, to the end of the
    body. The fingerprint uses only the public part, so this is a sanity
    gate: a secret packet whose tail does not parse will not import cleanly
    in any implementation, and its public part is not trusted."""
    n = len(body)
    usage = body[b]
    if usage == 0:
        # Unprotected: [secret MPIs][2-octet checksum of the secret material].
        if n - b < 5:
            return False
        mpis = body[b + 1:-2]
        return _mpi_run(mpis) is not None and \
            sum(mpis) % 65536 == int.from_bytes(body[-2:], "big")
    if 1 <= usage <= 13:
        # Legacy form: the usage octet is the cipher (simple MD5 S2K).
        # [cipher][IV][CFB-encrypted (secret MPIs + 2-octet checksum)].
        iv = CIPHER_BLOCK_SIZES.get(usage)
        return iv is not None and n - b >= 1 + iv + 16
    if usage in (253, 254, 255) or 100 <= usage <= 110:
        # [cipher][S2K type][type-specific fields][IV][CFB-encrypted data].
        if n - b < 3:
            return False
        iv = CIPHER_BLOCK_SIZES.get(body[b + 1])
        if iv is None:
            return False
        if usage in (253, 254, 255):
            s2k = S2K_FIELD_SIZES.get(body[b + 2])
            if s2k is not None:
                return n - b >= 2 + 1 + s2k + iv + 16
        # Private/experimental S2K types (100-110) have a variable field
        # size; only the minimum can be checked.
        return n - b >= 2 + 1 + iv + 16
    return False


def key_fingerprint(tag, body):
    """Return (fingerprint, problem) for a key packet (RFC 9580 section
    5.5.4.2). For a secret key or secret subkey packet (tag 5/7) the
    fingerprint is that of the embedded public part: key servers serve that
    part and consumers verify signatures against it. problem is None when
    the fingerprint is computable, else a human-readable reason."""
    if not body or body[0] != 4:
        return None, None
    if tag in (6, 14):
        return fingerprint_v4(body), None
    if tag in (5, 7):
        end = _public_material_end(body)
        if end is None:
            return None, "its public key material could not be parsed " \
                "(algorithm %d)" % body[5]
        if not _secret_tail_ok(body, end):
            return None, "its secret key protection fields could not be " \
                "parsed (S2K usage octet %d)" % body[end]
        return fingerprint_v4(body[:end]), None
    return None, None


def primary_fingerprints(path):
    """Return the version 4 primary key fingerprints of the key material.

    A primary key this check cannot fingerprint (an unsupported version, or
    a secret packet whose fields do not parse) fails the gate: its
    publication cannot be verified, and a key whose publication cannot be
    verified must not let the run through (a v4 key in the same secret
    cannot stand in for it). Subkeys are deliberately not checked, so their
    problems only merit a note."""
    try:
        text = open(path, encoding="utf-8", errors="replace").read()
    except OSError as error:
        fail("cannot read the key material: %s" % error)
    blocks = key_blocks(text)
    if not blocks:
        fail("no PGP key block in GPG_PRIVATE_KEY (expected an ASCII-armored key, or a single raw base64 key)")
    fprs = []
    for block in blocks:
        data = decode_block(block)
        if data is None:
            fail("the key material is not valid base64/OpenPGP data; the secret value may be corrupted")
        for tag, body in iter_packets(data):
            if tag not in (5, 6, 7, 14) or not body:
                continue
            if body[0] != 4:
                if tag in (5, 6):
                    fail("a version %d primary key is in GPG_PRIVATE_KEY, but this check "
                         "supports version 4 keys only; remove it from the secret if it is "
                         "not the release signing key, or verify its publication manually"
                         % body[0])
                print("note: a version %d subkey is not checked directly (this check "
                      "supports version 4 keys only)" % body[0], file=sys.stderr)
                continue
            fpr, problem = key_fingerprint(tag, body)
            if problem is not None:
                if tag in (5, 6):
                    fail("a primary key packet is malformed (%s); its fingerprint cannot be "
                         "derived, so its publication cannot be verified; check the secret "
                         "for corruption" % problem)
                print("note: a subkey packet is malformed (%s); it is not checked directly"
                      % problem, file=sys.stderr)
                continue
            if tag in (5, 6):
                if fpr not in fprs:
                    fprs.append(fpr)
            else:
                print("note: subkey %s is not checked directly; a lookup by the primary "
                      "fingerprint returns it" % fpr, file=sys.stderr)
    if not fprs:
        fail("no version-4 primary key packet found in GPG_PRIVATE_KEY")
    return fprs


def contains_fingerprint(path, fpr):
    try:
        text = open(path, encoding="utf-8", errors="replace").read()
    except OSError:
        return False
    for block in key_blocks(text):
        data = decode_block(block)
        if data is None:
            continue
        for tag, body in iter_packets(data):
            if tag == 6 and body and body[0] == 4 and fingerprint_v4(body) == fpr:
                return True
    return False


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "fprs":
        for fpr in primary_fingerprints(sys.argv[2]):
            print(fpr)
    elif len(sys.argv) == 4 and sys.argv[1] == "verify":
        sys.exit(0 if contains_fingerprint(sys.argv[3], sys.argv[2].upper()) else 1)
    else:
        fail("usage: parse_key.py fprs KEYFILE | verify FPR KEYFILE")


main()
PY

fprs_file="$workdir/fprs"
python3 "$workdir/parse_key.py" fprs "$key_file" > "$fprs_file" || exit 1

# One line per key: the fingerprint and its outcome (ok / mismatch /
# missing), so the step summary reports each key's actual result.
results_file="$workdir/results"
: > "$results_file"

url_base="${KEYSERVER_BASE_URL%/}/vks/v1/by-fingerprint"
status=0
for fpr in $(cat "$fprs_file"); do
    url="$url_base/$fpr"
    echo "Checking $fpr at $url"
    resolved=""
    attempt=1
    while :; do
        code=$(curl -sS -o "$workdir/response" -w '%{http_code}' \
            --max-time "$KEYSERVER_TIMEOUT" "$url" 2> "$workdir/curl.err") || code=000
        if [[ "$code" == "000" ]]; then
            echo "curl failed: $(tail -n 1 "$workdir/curl.err")" >&2
        fi
        if [[ "$code" == "200" ]]; then
            # A 200 is definitive: the block must actually carry the key we
            # asked for. A key server that answers a fingerprint lookup with
            # a different key will not fix itself on a retry.
            if python3 "$workdir/parse_key.py" verify "$fpr" "$workdir/response"; then
                resolved=ok
            else
                echo "ERROR: $url answered 200 but its key block is not $fpr" >&2
            fi
            break
        fi
        echo "HTTP $code; key not resolvable" >&2
        if [[ "$attempt" -ge "$KEYSERVER_ATTEMPTS" ]]; then
            break
        fi
        echo "Retrying in ${KEYSERVER_RETRY_DELAY}s (attempt $attempt of $KEYSERVER_ATTEMPTS)" >&2
        sleep "$KEYSERVER_RETRY_DELAY"
        attempt=$((attempt + 1))
    done
    if [[ -n "$resolved" ]]; then
        echo "Resolved $fpr"
        printf '%s\t%s\n' "$fpr" ok >> "$results_file"
    else
        status=1
        if [[ "$code" == "200" ]]; then
            outcome=mismatch
        else
            outcome=missing
        fi
        printf '%s\t%s\n' "$fpr" "$outcome" >> "$results_file"
        cat >&2 <<EOF
ERROR: public key $fpr does not resolve at $url after $KEYSERVER_ATTEMPTS attempt(s).

The release signing key's public part must be published before the run can
proceed; Maven Central's sync validation fetches it from the key server
(its absence rejected v0.6.0's upload, #131).

To publish the public key:
  1. Upload the ASCII-armored public key at https://keys.openpgp.org/upload
     (export it locally with: gpg --armor --export $fpr)
  2. Wait for the pool to propagate (minutes to hours), then confirm:
       curl -s -o /dev/null -w '%{http_code}\n' $url
     expecting 200
  3. Re-dispatch the release run.
EOF
    fi
done

if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
    {
        echo "### Key server"
        echo
        if [[ "$status" -eq 0 ]]; then
            echo "Every signing key in GPG_PRIVATE_KEY resolves at ${KEYSERVER_BASE_URL}:"
        else
            echo "**Not every signing key resolves at ${KEYSERVER_BASE_URL}; the run is failing before any build.** To publish the missing key: upload its ASCII-armored public part at https://keys.openpgp.org/upload, then re-dispatch the run."
        fi
        echo
        while IFS=$'\t' read -r fpr outcome; do
            case "$outcome" in
                ok)
                    echo "- ✅ \`$fpr\` resolves"
                    ;;
                mismatch)
                    echo "- ❌ \`$fpr\` — the key server answered 200 but its block is not this key"
                    ;;
                *)
                    echo "- ❌ \`$fpr\` — not resolvable after ${KEYSERVER_ATTEMPTS} attempt(s)"
                    ;;
            esac
        done < "$results_file"
    } >> "$GITHUB_STEP_SUMMARY"
fi

if [[ "$status" -ne 0 ]]; then
    echo "Key server check failed: not every signing key resolves at ${KEYSERVER_BASE_URL}" >&2
    exit 1
fi

echo "Every signing key in GPG_PRIVATE_KEY resolves at ${KEYSERVER_BASE_URL}"

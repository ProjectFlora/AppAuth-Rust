#!/usr/bin/env bash
# Verifies that the public part of the release signing key resolves at the
# key server before any release package is built.
#
# Maven Central's sync validation fetches the signing key's public key from
# a key server; v0.6.0's upload was rejected because the freshly created key
# was not there yet (#131). This check fails the run, before any build job
# starts, if the public key is not resolvable by fingerprint.
#
# It covers every *primary* key in GPG_PRIVATE_KEY. A key server lookup by
# primary fingerprint returns the whole key block, subkeys included, and
# keys.openpgp.org does not resolve subkey fingerprints on the
# by-fingerprint endpoint, so subkeys are deliberately not checked.
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
# (v4: SHA-1 of 0x99 + 2-octet body length + body).
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
            return  # truncated; stop
        yield tag, data[i:i + length]
        i += length


def fingerprint_v4(body):
    return hashlib.sha1(b"\x99" + len(body).to_bytes(2, "big") + body).hexdigest().upper()


def primary_fingerprints(path):
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
            if tag not in (6, 14) or not body:
                continue
            if body[0] != 4:
                print("note: skipping a version %d key (this check supports version 4 keys only; "
                      "verify its publication manually)" % body[0], file=sys.stderr)
                continue
            fpr = fingerprint_v4(body)
            if tag == 14:
                print("note: subkey %s is not checked directly; a lookup by the primary "
                      "fingerprint returns it" % fpr, file=sys.stderr)
            elif fpr not in fprs:
                fprs.append(fpr)
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
    else
        status=1
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
        echo "The signing key's public part resolves at ${KEYSERVER_BASE_URL}:"
        echo
        for fpr in $(cat "$fprs_file"); do
            echo "- \`$fpr\`"
        done
    } >> "$GITHUB_STEP_SUMMARY"
fi

if [[ "$status" -ne 0 ]]; then
    echo "Key server check failed: not every signing key resolves at ${KEYSERVER_BASE_URL}" >&2
    exit 1
fi

echo "Every signing key in GPG_PRIVATE_KEY resolves at ${KEYSERVER_BASE_URL}"

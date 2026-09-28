### Description

`SignedCms.CheckSignature(verifySignatureOnly: true)` accepts a SignedData message whose `encapContentInfo.eContentType` differs from the value of its signed content-type attribute. Because `eContentType` is not covered by the signature, anyone can change the content type of a validly signed message without the signing key: `CheckSignature` still succeeds, and `SignedCms.ContentInfo.ContentType` reports the new type.

RFC 5652 §11.1: "The content-type attribute value MUST match the SignedData encapContentInfo eContentType value." The attribute is what authenticates `eContentType`.

### Reproduction Steps

1. Sign any content with `openssl cms -sign -binary -md sha256 -nodetach -outform DER -in msg.txt -signer cert.pem -inkey key.pem -out signed.der`.
2. Change one byte of `eContentType` (the first `06 09 2a 86 48 86 f7 0d 01 07 01` in the file) so it reads 1.2.840.113549.1.7.5, and save it as `relabeled.der`. The signed attributes are untouched.
3. Run:

```csharp
using System.Security.Cryptography.Pkcs;

foreach (var path in args)
{
    var cms = new SignedCms();
    cms.Decode(File.ReadAllBytes(path));
    string verdict;
    try { cms.CheckSignature(verifySignatureOnly: true); verdict = "signature valid"; }
    catch (Exception e) { verdict = "refused: " + e.Message; }
    Console.WriteLine($"{path}: eContentType {cms.ContentInfo.ContentType.Value}, {verdict}");
}
```

### Expected behavior

`relabeled.der` is refused: its content-type attribute (id-data) does not match its `eContentType`.

### Actual behavior

```
signed.der: eContentType 1.2.840.113549.1.7.1, signature valid
relabeled.der: eContentType 1.2.840.113549.1.7.5, signature valid
```

### Regression?

Not known.

### Known Workarounds

Compare the content-type signed attribute with `ContentInfo.ContentType` after `CheckSignature`.

### Configuration

System.Security.Cryptography.Pkcs 10.0.12 on .NET 10, and 11.0.0-rc.1.26425.128 on .NET 11 RC 1; macOS on Apple Silicon.

### Other information

An application that verifies with `SignedCms` and then acts on `ContentInfo.ContentType` can be made to treat content signed as one type as another. We have not found a specific exploitable application and judge it low severity, which is why this is filed publicly.

In the same tests `CheckSignature` also accepted signed attributes with no content-type attribute or with two of them (RFC 5652 §5.3, §11.1), a countersignature among the signed attributes (§11.4), an RSA signature one byte shorter than the modulus (RFC 8017 §8.2.2, so one signature has two encodings), and a trailing byte after the message. Those need the signer's key or are malleability rather than forgery.

Suggested fix: when signed attributes are present, require exactly one content-type attribute and compare its value with the encapsulated content type in `CheckSignature`.

Found by differential testing of seven CMS verifiers against a specification of RFC 5652 written and proved in Lean: https://github.com/keithadler/lean-pkcs7cms (`test/crosscheck`).

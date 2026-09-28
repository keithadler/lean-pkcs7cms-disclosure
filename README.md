# lean-pkcs7cms: disclosure record

Findings from [lean-pkcs7cms](https://github.com/keithadler/lean-pkcs7cms), which tests seven CMS (PKCS #7)
signature verifiers against a specification of RFC 5652 proved in Lean.

## What happened

On 2026-09-28 the crosscheck showed that OpenSSL, LibreSSL and .NET accept a signed message whose content type
(`eContentType`, outside the signed bytes) was changed after signing, with no key. The first plan was private
disclosure, and the files here were written for it:

- `1-openssl-security.txt`, `2-libressl-security.txt`, `3-msrc-dotnet.txt`: the private reports, never sent.
- `relabel-repro.sh`, `dotnet-repro/`: the reproductions.
- `commitment/findings-2026-09-28.txt`: everything above sealed in one file with a random salt.

We judged the flaw low severity (it needs an application that acts on the content type after verifying), so it
was reported publicly instead, the same day:

- OpenSSL: https://github.com/openssl/openssl/issues/33022
- LibreSSL: https://github.com/libressl/portable/issues/1412
- .NET: https://github.com/dotnet/runtime/issues/134822

The private drafts say we would wait before publishing; that plan was replaced by the public reports above.

## Checking the sealed file

```sh
shasum -a 256 commitment/findings-2026-09-28.txt
```

prints

    06cce00a1e2d4c2b8cc88708c038ccf5502ec230f49171b6878e0711ae35916f

`commitment/commitment-token.der` is an RFC 3161 timestamp token from DigiCert's public timestamp server for
that hash, granted 2026-09-28 22:03:34 UTC. OpenSSL checks it with

```sh
openssl ts -reply -in commitment/commitment.tsr -text
```

and lean-pkcs7cms verifies it in Lean's kernel (`CMS/Real.lean`, `findings_stamped`).

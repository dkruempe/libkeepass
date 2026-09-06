# Security Policy

libkeepass is a security-sensitive library that handles encrypted password
databases. We take security issues seriously and appreciate your help
disclosing them responsibly.

## Supported Versions

Security updates are provided for the latest minor release and, when the
findings warrant it, backported to the most recent previous minor release.

| Version | Supported |
|---|---|
| 0.2.x | Yes |
| < 0.2 | No |

## Reporting a Vulnerability

Please do not publish exploit details in public issue titles or descriptions
before the issue is fixed. Open a GitHub issue at
<https://github.com/dkruempe/libkeepass/issues> and:

- keep the title generic (e.g. "Security issue in …"),
- describe the impact and include reproduction steps in the issue body.

We will respond within 3 business days and coordinate a fix before the issue
is made public.

## Security Considerations For This Project

- **Ciphers and KDFs:** the library implements AES-KDF, Argon2d/id, Twofish,
  Salsa20 and ChaCha20. Algorithm selection follows the database headers;
  databases using unknown or insecure ciphers/KDFs are rejected with a
  `FormatError` at import time.
- **Key material in memory:** transformed keys are cached on the `Database`
  object to avoid re-running expensive KDFs on export. The cached keys are
  stored in `SecureBuffer<32>` and the buffer contents are wiped when the
  key is released. Transient transformed keys, HMAC keys, master keys and
  inner random stream keys are zeroized immediately after their last use in
  the import/export code paths. Allocation uses best-effort `mlock`/
  `VirtualLock`, so memory locking is not guaranteed on all platforms (see
  `docs/key-derivation.md`).
- **Entry data in memory:** secret entry fields (passwords, protected
  strings) are stored in `secure_string` buffers that are wiped on release
  and are never kept in inline (SSO) storage.
- **Third-party crypto:** AES and hashes are provided by OpenSSL; Argon2 by
  the reference `libargon2`. We do not roll our own production-grade
  primitives beyond the format-specific ciphers listed above.

## Disclosure Policy

- We will coordinate a fix and a release with you.
- We will credit the reporter in the advisory unless anonymity is requested.
- We aim to publish a summary through GitHub Security Advisories once a fix
  is released.

## Comments

If you have suggestions for improving this policy or the security posture of
the library in general, please open a regular issue (non-security related).
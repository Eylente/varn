# Changelog
## [0.1.1] - YYYY-MM-DD
### Added
- Hash verification page: check a password against an existing hash (Argon2id, Argon2i, Argon2d, scrypt and PBKDF2 in PHC format, bcrypt)
- Settings page: interface language and resource limits (threads and share of memory)
### Changed
- Batch hashing now uses half of the logical threads by default instead of all of them, and counts the internal threads of Argon2
- A single hash that needs more memory than the configured share is refused instead of being computed
- Warnings and error messages from the cryptographic core are now translated in the interface
- `settings.json` now also stores the resource limits
### Security
- Hash verification rejects crafted hash strings with extreme parameters (memory, iterations) before computing anything

## [0.1.0] - 2026-10-21
First release under the name Varn (formerly Basalt).
### Added
- Avalonia interface (English and Russian), dark theme
- scrypt, PHC and hash + salt output, batch hashing from Excel
- RSA and ECDSA key pairs (PEM, JWK), random secrets
- JWT: verification (HS, RS, PS, ES) and token generation
- TOTP: verification with time drift, `otpauth://` links and QR codes
### Fixed
- JWT verification no longer treats unknown algorithms as HS256; `alg: none` and algorithm confusion are flagged
- bcrypt's 72-byte password limit is reported
# Changelog

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
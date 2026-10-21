<div align="center">

<img src="docs/icon.png" width="96" alt="Varn logo" />

# Varn

**An offline cryptography toolkit for developers.**
Hash passwords, generate keys, inspect JWTs and test one-time codes. Everything runs on your computer.

[English](README.md) · [Русский](README.ru.md)

</div>

> Varn was previously called **Basalt**.

## Why

Many everyday crypto tasks (hashing a test password, decoding a token, checking a TOTP secret) are usually done on websites. Pasting real secrets into a website is a bad habit. Varn does the same jobs locally and never touches the network.

## Features

- **Password hashing**: Argon2id, bcrypt, PBKDF2 (SHA-256/512) and scrypt, with sensible defaults (Argon2id t=3, 64 MiB, p=4; PBKDF2 600,000 iterations; bcrypt cost 12; scrypt N=2^16). Output as a PHC string or as separate hash, salt and parameters. Legacy SHA-256, MD5 and SHA-1 are available only to emulate old systems.
- **Batch hashing from Excel**: hash a whole column of passwords (`Login`, `Password`) and get hash, salt, algorithm, parameters and notes back. Parallelism is limited by available memory, and the run can be cancelled.
- **Keys**: random secrets (128/256/512 bit as Base64, Hex or Base32) and RSA (2048/3072/4096) or ECDSA (P-256/384/521) key pairs. Export as PEM (PKCS#8 and SPKI) or JWK, optionally with an AES-256 encrypted private key.
- **JWT**: decode and verify HS256/384/512, RS256/384/512, PS256/384/512 and ES256/384/512, or create signed tokens. Warns about `alg: none`, algorithm-confusion keys and weak secrets, and shows `iat`, `nbf` and `exp` with their status.
- **TOTP (RFC 6238)**: live codes with previous and next codes, SHA-1/256/512, 6-8 digits, 15/30/60 s periods, verification with a configurable time drift, and `otpauth://` links with QR codes for authenticator apps.
- Cross-platform UI built with Avalonia, in English and Russian.

## Screenshots

![Password hashing](docs/screenshots/hash.png)
![Excel batch](docs/screenshots/excel.png)
![Keys](docs/screenshots/keys.png)
![JWT](docs/screenshots/jwt.png)
![TOTP](docs/screenshots/totp.png)

## Download

Download the latest Windows build from the [Releases](https://github.com/Eylente/varn/releases) page: an installer (no administrator rights needed) or a portable ZIP. Both are self-contained and do not require .NET to be installed. Always download Varn from this page only, and compare the SHA-256 checksums from the release notes. On Linux and macOS you can build from source (see below); these platforms have not been tested yet.

## Build from source

You need the [.NET 10 SDK](https://dotnet.microsoft.com/download).

```bash
git clone https://github.com/Eylente/varn.git
cd varn
dotnet run --project Varn.Desktop
dotnet test
```

## Project layout

| Project | Description |
|---|---|
| `Varn.Core` | Hashing, keys, JWT and TOTP logic. No UI dependencies. |
| `Varn.Desktop` | The Avalonia desktop app (MVVM). |
| `Varn.Core.Tests` | xUnit tests, including known-answer vectors (RFC 6238, RFC 7914, PBKDF2-SHA256, a jwt.io token). |

## Security notes and limitations

- Varn works fully offline. The only thing it saves to disk is the interface language (`settings.json` in your user profile).
- Varn has **not been independently audited**. It is a tool for development and diagnostics, so do not use it to create secrets that protect real systems.
- Cryptography comes from well-known libraries (.NET, Konscious.Security.Cryptography for Argon2, BCrypt.Net-Next, BouncyCastle for scrypt, Otp.NET), not from custom implementations.
- Passwords and secrets are entered as .NET strings, which cannot be wiped from memory. Varn wipes the byte buffers it creates itself and clears copied values from the clipboard after 30 seconds. This does not protect against someone who can read your computer's memory, and clipboard managers (such as Windows clipboard history) keep their own copies.
- Legacy hashes (MD5, SHA-1, plain SHA-256) are insecure. bcrypt only uses the first 72 bytes of a password.

## Ideas for later

- Verify an existing hash against a password
- Ed25519 keys
- Tested Linux and macOS builds

## License

MIT. See [LICENSE.txt](LICENSE.txt). Third-party components are listed in [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).

## Name and logo

The source code is licensed under the MIT License. The name "Varn" and the Varn logo (`docs/icon.png` and the icon files in `Varn.Desktop/Assets/`) are © 2026 Eylente, all rights reserved, and are not covered by the MIT License. If you fork Varn or distribute a modified version, please use a different name and logo so it cannot be mistaken for the official builds.
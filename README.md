# SynoKit

Transport + security core shared between **SynologyMonitor** and
**SynologyPhotosManager**. Extracted so DSM auth/credential code lives in one
place instead of being copied into each app (see the plan's "장기 보수성" rule).

## What's in scope

- `SynologyClient` — runtime API discovery (`SYNO.API.Info`), login/logout with
  **2FA (OTP)** support, and generic authenticated requests (`requestData`,
  `perform`). Feature APIs (`SYNO.Foto.*`, `SYNO.DownloadStation.*`) are built
  by the host apps on top of this — not here.
- `SynologyAPIError` — transport/auth errors + DSM **auth** code mappers.
  App-specific code tables (e.g. DownloadStation 400–408, which collide with
  auth codes) stay in the host app.
- `SecureLocalStore` / `CredentialStore` / `TrustedCertificateStore` — AES-GCM
  local file storage (Keychain intentionally not used) + TOFU cert pinning.
- `CertificateTrustDelegate` / `NetworkSessionProvider` — per-host TLS trust,
  never relaxed globally.

Host apps set `SecureLocalStore.appDirectoryName` once at launch so the two
apps don't share an on-disk store.

## Tests

Run the dependency-free check runner:

```
swift run SynoKitChecks
```

Exits non-zero if any check fails (32 checks: core types, secure store,
client auth/discovery/error-mapping over a stubbed transport).

> **Why not `swift test`?** This machine has only the Command Line Tools, not
> full Xcode, so SwiftPM can't load XCTest or discover swift-testing `@Test`
> functions (they compile and link but silently run zero tests). The
> `SynoKitChecks` executable sidesteps that and runs anywhere the compiler does.
> Once the app is developed in Xcode, these can also be mirrored as
> XCTest/swift-testing targets.

## Status

Foundation only. Next: the SynologyPhotosManager app target (needs Xcode) and
`FotoAPI` built on `SynologyClient`, per `SynologyPhotosManager-Plan.md`.
Migrating SynologyMonitor to depend on this package is a tracked follow-up
(verify its full feature set after switching).

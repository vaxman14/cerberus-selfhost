# Cerberus for Windows

The Windows desktop edition runs the complete Cerberus stack without Docker.
The WPF/WebView2 shell supervises four loopback-only components:

- the existing Cerberus API, local-auth UI, SQLite history, reports, and AI Lab;
- the Lighthouse, Nuclei, and sqlmap worker;
- OWASP ZAP with its own private API key; and
- pinned Python, Node, Java, and scanner runtimes.

All application data and secrets live under `%LOCALAPPDATA%\Cerberus`. The
launcher gives the secret directory a current-user-only Windows ACL and kills
the complete process trees when the desktop window closes.

## Build on Windows

Requirements: Windows 10/11 x64, Python 3.12, .NET 8 SDK, Go 1.26, Git, and
Inno Setup 6. Build outputs should be placed on the designated build drive:

```powershell
./desktop/windows/build-runtime.ps1 `
  -BuildRoot D:\JosiDrive\Build\cerberus-windows `
  -StageRoot D:\JosiDrive\Artifacts\cerberus-windows-stage

$env:CERBERUS_STAGE_DIR='D:\JosiDrive\Artifacts\cerberus-windows-stage'
$env:CERBERUS_INSTALLER_DIR='D:\JosiDrive\Artifacts\cerberus-windows-installer'
$env:CERBERUS_VERSION='0.2.2'
& 'C:\Program Files (x86)\Inno Setup 6\ISCC.exe' desktop\windows\installer.iss
```

`runtime.lock.json` pins every third-party runtime by version/commit and every
downloaded archive by SHA-256. The GitHub Actions workflow performs the same
build and publishes the installer plus its SHA-256 checksum.

## Signing

Unsigned development installers are intentionally labeled as such. Production
publishing must Authenticode-sign `Cerberus.exe`, every project-owned sidecar,
and the final installer with the CTF Designs code-signing certificate. Never
put certificate material in the repository; use GitHub environment secrets or
an external signing service.

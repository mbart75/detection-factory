# Changelog

All notable changes to this project. Releases are tagged on GitHub; see
[Releases](https://github.com/mbart75/detection-factory/releases).

## [Unreleased]

### Security
- `win_unmanaged_powershell_load`: the PowerShell 7 exclusion matched any
  image ending in `\pwsh.exe`, so an implant renamed `pwsh.exe` in a
  user-writable folder loaded the PowerShell engine without an alert. The
  exclusion is now anchored to the MSI and Microsoft Store install paths.

### Added
- Evasion variants in the test manifest: the pinned sample is replayed with
  event fields rewritten, and each variant must fire or stay silent
  (`docs/decisions.md`, decision 11).

## [1.0.0] - 2026-10-21
First public release.

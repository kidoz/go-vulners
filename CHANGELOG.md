# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2025-02-10

### Added

- SBOM audit endpoint (`POST /api/v4/audit/sbom`) — upload SPDX or CycloneDX JSON files for vulnerability analysis
- `AuditService.SBOMAudit(ctx, io.Reader, ...AuditOption)` method
- Multipart file upload support in the HTTP transport (`doPostMultipart`)
- `SBOMAuditResult`, `SBOMPackageResult`, and `SBOMAdvisory` types
- `handleResponseDirect` for v4 endpoints that use `{"result": T}` response format
- GoDoc example `ExampleAuditService_SBOMAudit`
- Integration test for SBOM audit with sample SPDX file (`testdata/spdx.json`)

### Fixed

- golangci-lint v2 compatibility: updated CI action to `@v7`, fixed config schema

## [1.0.0] - 2025-02-09

### Added

- Initial release
- Search service: bulletins, exploits, references, history
- Audit service: software, host, Linux, Windows KB, Windows full
- Archive service: fetch collections and updates
- Webhook and subscription management
- STIX bundle generation
- Report service: vulnerability summaries, IP summaries, scan lists
- Misc service: CPE search, AI scoring, autocomplete, suggestions
- VScanner client: project, task, and result management
- Built-in rate limiting with dynamic server-side adjustment
- Automatic retry with exponential backoff and jitter
- Context support for cancellation and timeouts
- Redirect security (blocks host changes and HTTPS downgrade)
- Zero external dependencies

[1.1.0]: https://github.com/vulnersCom/go-vulners/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/vulnersCom/go-vulners/releases/tag/v1.0.0

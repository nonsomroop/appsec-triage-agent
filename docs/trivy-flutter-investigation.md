# Flutter dependency investigation

Verified on 9 November 2026 against repository commit
`0a874673d24ba9fa35d686b494fb430174ace125`, using Trivy 0.76.0.

## Root cause

The vulnerability was absent from the downloaded Trivy database. Its schema
version was 2 and its update timestamp was
`2026-11-08T18:58:44.715199225Z`. A read-only search of the database found no
`image_picker_android`, `GHSA-98v2-f47x-89xw`, or `CVE-2024-54462` records.
Pub ecosystem records were present.

The native JSON result contained 104 packages from
`sarnfan/pubspec.lock`, including these exact entries.

| Package | Version | Relationship |
| --- | --- | --- |
| image_picker | 1.1.2 | direct |
| image_picker_android | 0.8.12+3 | indirect |

The native result had no vulnerabilities. This establishes that the missing
finding originated before application normalization, storage or display.
The production invocation had no severity restriction. Low severity is also
explicitly included by the updated adapter.

The published maintainer advisory includes this installed version in its affected
range and identifies `0.8.12+18` as the fix.
[Maintainer advisory](https://github.com/flutter/packages/security/advisories/GHSA-98v2-f47x-89xw)

## Additional advisory source evaluation

The global GitHub advisory page and API for the supplied GHSA ID returned 404,
although the repository advisory was accessible. Trivy's GHSA importer ingests
GitHub-reviewed records, including the Pub ecosystem.
[Trivy GHSA importer](https://github.com/aquasecurity/trivy-db/blob/main/pkg/vulnsrc/ghsa/ghsa.go)

OSV returned a record when looked up by CVE ID. Its affected entry describes
the Flutter packages Git repository and commit ranges, without a Pub
package mapping. A live OSV query for ecosystem `Pub`, package
`image_picker_android`, version `0.8.12+3` returned no matches. The Pub.dev
package advisory API also returned an empty advisory list.
[OSV record](https://osv.dev/vulnerability/CVE-2024-54462)

An optional OSV source could broaden coverage for correctly indexed packages.
This case requires upstream package/advisory indexing or a separately validated
mapping from package releases to affected Git commits. Adding a package/version
OSV query alone would still miss this advisory. Production detection continues
to use Trivy's native matching, with the coverage limitation visible in reports.

## Changes

- Request the full native package inventory and retain exact versions,
  relationships, ecosystems and manifest locations.
- Record scanner version and database timestamps after the scan's normal update.
- Include all severity levels and unfixed vulnerabilities explicitly.
- Preserve findings from dependency files whose directory names overlap source
  excerpt exclusion rules. Dependency metadata contains no source excerpts.
- Preserve native advisory source and vendor IDs in normalized findings.
- Capture bounded scanner diagnostics and surface generic warnings without
  persisting raw diagnostic text.
- Display a searchable dependency inventory and distinguish detected
  vulnerabilities, zero database matches, partial analysis, unsupported native
  analysis, unconfirmed analysis and failure.

A successful exit establishes that the scanner finished its configured operation.
Package inventory establishes parsing. Neither proves that the database contains
every relevant advisory. When no dependency files are reported, the app marks
coverage unconfirmed. It cannot infer whether an arbitrary file format was
unsupported, ignored, or absent. Explicit native unsupported-analysis warnings
are displayed separately.

The existing scan status values and older report compatibility are retained.
More detailed dependency outcomes live in `scan.coverage.trivy.analysis_status`.
Database-source limitations remain visible even when the scan completed.

## Regression checks

The representative Flutter lockfile lives in
`tests/fixtures/flutter/pubspec.lock`. The opt-in native test asserts that
Trivy extracts the direct and transitive versions. It makes no assertion that a
database missing the advisory must detect it.

```sh
APPSEC_TRIVY_INTEGRATION=1 pytest tests/test_sca.py -k native_flutter
```

Offline adapter tests cover Low severity through CLI export and persisted history,
zero findings with package evidence, Pub/Python/npm metadata, partial inventories,
native warnings, unsupported analysis, execution errors and missing targets.
These adapter-contract fixtures do not manufacture a native Flutter detection.

The application intentionally excludes SCA from source-based AI triage. Zero AI
reviews for a dependency scan is expected independently of vulnerability count.

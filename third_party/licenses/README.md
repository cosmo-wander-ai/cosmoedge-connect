# Third-party license materials

This directory preserves license, notice, patent and attribution files from the
exact local Go dependency versions used by the two release commands. Texts are
copied byte-for-byte, without relicensing or replacing upstream attribution.

The selection was computed from `go list -m -json all` and the package dependency
graphs of `cmd/cosmoedge-connect` and `cmd/cosmoedge-mcp` with `CGO_ENABLED=0` for macOS arm64,
macOS amd64, Windows amd64 and Linux amd64. Graph-only development/test modules
are recorded in [index.json](index.json) but are not asserted to be linked into
release binaries. Linux dependency coverage is not a Linux support claim.

The index records module versions, Go checksums, original relative paths and
SHA-256 for every copied file. It contains no local cache or personal paths.
Root and non-testdata component notices are retained; some notices can describe
upstream assets not used by these commands. The upstream text remains authoritative.

| Module | Version | Preserved texts |
| --- | --- | --- |
| `github.com/dustin/go-humanize` | `v1.0.1` | [LICENSE](github.com/dustin/go-humanize@v1.0.1/LICENSE) |
| `github.com/google/jsonschema-go` | `v0.4.3` | [LICENSE](github.com/google/jsonschema-go@v0.4.3/LICENSE) |
| `github.com/google/uuid` | `v1.6.0` | [LICENSE](github.com/google/uuid@v1.6.0/LICENSE) |
| `github.com/mattn/go-isatty` | `v0.0.20` | [LICENSE](github.com/mattn/go-isatty@v0.0.20/LICENSE) |
| `github.com/modelcontextprotocol/go-sdk` | `v1.8.0` | [LICENSE](github.com/modelcontextprotocol/go-sdk@v1.8.0/LICENSE) |
| `github.com/ncruces/go-strftime` | `v1.0.0` | [LICENSE](github.com/ncruces/go-strftime@v1.0.0/LICENSE) |
| `github.com/remyoudompheng/bigfft` | `v0.0.0-20230129092748-24d4a6f8daec` | [LICENSE](github.com/remyoudompheng/bigfft@v0.0.0-20230129092748-24d4a6f8daec/LICENSE) |
| `github.com/segmentio/asm` | `v1.1.3` | [LICENSE](github.com/segmentio/asm@v1.1.3/LICENSE) |
| `github.com/segmentio/encoding` | `v0.5.4` | [LICENSE](github.com/segmentio/encoding@v0.5.4/LICENSE), [json/fuzz/LICENSE](github.com/segmentio/encoding@v0.5.4/json/fuzz/LICENSE) |
| `github.com/yosida95/uritemplate/v3` | `v3.0.2` | [LICENSE](github.com/yosida95/uritemplate/v3@v3.0.2/LICENSE) |
| `golang.org/x/oauth2` | `v0.35.0` | [LICENSE](golang.org/x/oauth2@v0.35.0/LICENSE) |
| `golang.org/x/sync` | `v0.20.0` | [LICENSE](golang.org/x/sync@v0.20.0/LICENSE), [PATENTS](golang.org/x/sync@v0.20.0/PATENTS) |
| `golang.org/x/sys` | `v0.44.0` | [LICENSE](golang.org/x/sys@v0.44.0/LICENSE), [PATENTS](golang.org/x/sys@v0.44.0/PATENTS) |
| `golang.org/x/time` | `v0.15.0` | [LICENSE](golang.org/x/time@v0.15.0/LICENSE), [PATENTS](golang.org/x/time@v0.15.0/PATENTS) |
| `modernc.org/libc` | `v1.73.4` | [AUTHORS](modernc.org/libc@v1.73.4/AUTHORS), [LICENSE](modernc.org/libc@v1.73.4/LICENSE), [LICENSE-3RD-PARTY.md](modernc.org/libc@v1.73.4/LICENSE-3RD-PARTY.md) |
| `modernc.org/mathutil` | `v1.7.1` | [AUTHORS](modernc.org/mathutil@v1.7.1/AUTHORS), [LICENSE](modernc.org/mathutil@v1.7.1/LICENSE), [mersenne/AUTHORS](modernc.org/mathutil@v1.7.1/mersenne/AUTHORS), [mersenne/LICENSE](modernc.org/mathutil@v1.7.1/mersenne/LICENSE) |
| `modernc.org/memory` | `v1.11.0` | [AUTHORS](modernc.org/memory@v1.11.0/AUTHORS), [LICENSE](modernc.org/memory@v1.11.0/LICENSE), [LICENSE-GO](modernc.org/memory@v1.11.0/LICENSE-GO), [LICENSE-LOGO](modernc.org/memory@v1.11.0/LICENSE-LOGO), [LICENSE-MMAP-GO](modernc.org/memory@v1.11.0/LICENSE-MMAP-GO) |
| `modernc.org/sqlite` | `v1.53.0` | [AUTHORS](modernc.org/sqlite@v1.53.0/AUTHORS), [LICENSE](modernc.org/sqlite@v1.53.0/LICENSE), [SQLITE-LICENSE](modernc.org/sqlite@v1.53.0/SQLITE-LICENSE) |

## Go runtime and vendored standard-library components

The build toolchain used to create this inventory is `go1.26.5`. Its root
license/patent files and vendored standard-library component notices are included:

- [LICENSE](go-go1.26.5/LICENSE)
- [PATENTS](go-go1.26.5/PATENTS)
- [src/vendor/golang.org/x/crypto/LICENSE](go-go1.26.5/src/vendor/golang.org/x/crypto/LICENSE)
- [src/vendor/golang.org/x/crypto/PATENTS](go-go1.26.5/src/vendor/golang.org/x/crypto/PATENTS)
- [src/vendor/golang.org/x/net/LICENSE](go-go1.26.5/src/vendor/golang.org/x/net/LICENSE)
- [src/vendor/golang.org/x/net/PATENTS](go-go1.26.5/src/vendor/golang.org/x/net/PATENTS)
- [src/vendor/golang.org/x/sys/LICENSE](go-go1.26.5/src/vendor/golang.org/x/sys/LICENSE)
- [src/vendor/golang.org/x/sys/PATENTS](go-go1.26.5/src/vendor/golang.org/x/sys/PATENTS)
- [src/vendor/golang.org/x/text/LICENSE](go-go1.26.5/src/vendor/golang.org/x/text/LICENSE)
- [src/vendor/golang.org/x/text/PATENTS](go-go1.26.5/src/vendor/golang.org/x/text/PATENTS)

## Updating

When a dependency, build target, build tags, CGO setting or Go toolchain changes,
recompute the package graph and refresh these originals before distribution.
Compare final binaries with `go version -m` as a package check. A checksum index
binds the included texts but does not itself grant redistribution rights.

The MCP Go SDK version includes its upstream licensing-transition statement;
retain that complete file instead of labeling the entire dependency MIT or
Apache-2.0. The SQLite and modernc libc component notices are likewise retained
alongside each module's primary license.

These materials do not license external device firmware, model artifacts,
captured media or a separately installed Python/AI client runtime.

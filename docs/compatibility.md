# Compatibility and validation status

The first public release, `v0.1.0-alpha.1`, is a **source preview** for developers.
It provides the local service, stdio MCP adapter, WorkBuddy integration and
development-package tooling. The version's GitHub release links the checks for
its exact source commit.

## Platform checks

The [CI workflow](https://github.com/cosmo-wander-ai/cosmoedge-connect/actions/workflows/ci.yml)
defines the checks below. A target is verified only when its job succeeds for
the source commit being used; consult that run's results and recorded skips.

| Target | Automated check | Boundary |
| --- | --- | --- |
| Linux | Go tests, vet, race checks, Python tests, documentation links and public command builds | No certified Linux desktop installation package |
| macOS | Go tests, vet, Python tests, documentation links and public command builds | Installer unit tests do not establish native desktop or real-device acceptance |
| Windows | Go tests, vet, native Python/DACL checks, documentation links and public command builds | Client GUI and connected-device workflows need separate acceptance |
| Windows isolated lifecycle | Build paired package, install with `-NoStartup`, start/stop/restart, real stdio MCP and cleanup | No device, WorkBuddy GUI or login-shortcut registration |
| Synthetic MCP example | Tool discovery, image/report content, request recovery and context isolation | Synthetic service and media; no device connection or visual-model evaluation |

## Package and device acceptance

Build each service, adapter and WorkBuddy payload from one clean source commit.
Retain its manifest and verify paired versions and file hashes. A package rebuilt
from a different commit is a new candidate, even if its product behavior is
intended to be unchanged.

This source preview does not certify a public binary installation, a particular
AI client's attachment display, or real-device changes. macOS distribution
signing/notarization, client-native delivery, confirmation, one intended device
write, fresh readback and restoration must be measured for the exact package.
See [testing](testing.md) for those cases and [installation](installation.md)
for source and development-package instructions.

## Product scope

- One local user and one selected CosmoEdge device.
- Counts describe retained records actually read, with explicit gaps or limits;
  they do not establish historical uptime or incident causes.
- Still-image acquisition with host-model interpretation, preserving the original
  image for follow-ups; no continuous video reasoning claim.
- Changes use existing sources and installed algorithms and require local
  business confirmation. Restoring configuration does not erase event history.
- Remote/cloud MCP, multi-user hosting, multi-device routing, WeChat, scheduled
  inspection, training and model conversion are outside this release.

Record future acceptance against a specific release and manifest, separating
source checks, installation, actual client delivery and device behavior. Preserve
only the evidence needed to reproduce open issues or substantiate a current
release claim; superseded experiment diaries are not a support record.

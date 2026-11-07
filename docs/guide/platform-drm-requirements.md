# Platform DRM Requirements

Which CDM a title needs depends on the service **and the endpoint**: the same
brand may give SD to a browser CDM, FHD to Widevine L3, and UHD only to
Widevine L1 or PlayReady SL3000 — and may change the rule per endpoint, per
catalogue, or without notice.

This page records what is known about **the services unshackle currently
ships adapters for**, combining the maintainers' own verified results with
community reports gathered between July and November 2026. It is a starting
point for choosing a CDM in your
[`cdm` configuration](drm-and-cdm.md#selecting-which-device-to-use-the-cdm-config),
not a guarantee: reports conflict, platforms change endpoints, and a level
that licenses is not always the level that receives the highest-quality
manifest.

!!! warning "Unverified and time-sensitive"
    Community entries were reported by users testing individual endpoints.
    Treat every such row as "reported working at the time" and retest before
    relying on it. Prefer the lowest security level that works: a stronger
    device is not automatically offered a better manifest.

## Terms

| Term | Meaning |
|------|---------|
| **L1 / L3** | Widevine security levels. L1 is hardware-backed; L3 is software-only. |
| **SL2000 / SL3000** | PlayReady security levels. SL3000 is the hardware-backed tier roughly comparable to L1. |
| **Chrome CDM** | The Widevine CDM built into Chrome. Browser endpoints often cap it regardless of the license. |
| **Clear / No encryption** | The tracks need no CDM, though a service adapter is still needed to fetch them. |

## Current services

Max path is the adapter ceiling — not every title or account offers that
high. Where a community report exists for a service, it is noted; the
maintainers' verified results are the baseline everywhere else.

| Tag | Service | DRM path | Max path | Community report |
|-----|---------|----------|----------|------------------|
| `AMZN` | Prime Video | Widevine L3 (web player) | 1080p AVC SDR; no UHD/HDR device path | **Yes — see below** |
| `ATVP` | Apple TV+ | PlayReady (SL3000 path verified) | 1080p | None in the reviewed reports |
| `AUBC` | ABC iview | None (clear HLS) | Best clear representation (typically ≤1080p) | None |
| `BINGE` | Binge | Widevine L3 (web profile) | Best DASH rung the web profile returns (often 720p–1080p) | None |
| `DSNP` | Disney+ | Widevine (HLS) | Best HLS rung the account receives | Asked about, but no requirement was reported |
| `HMAX` | HBO Max | Widevine; PlayReady 1080p tracked separately | 1080p when the account advertises it, else 720p | None |
| `NF` | Netflix | Widevine L3 (web player, MSL) | 1080p H.264 SDR; no HDR/Dolby Vision/PlayReady path | None |
| `NINE` | 9Now | None (clear DASH) | Best clear representation (typically ≤1080p) | None |
| `PMTP` | Paramount+ | Widevine (DASH) | Best DASH rung the account receives | None |
| `SBS` | SBS On Demand | None (clear HLS) | Best clear representation (1080p when published) | None |
| `SEVEN` | 7plus | Widevine (DASH preferred) | Best DASH rung the account receives | None |
| `STAN` | Stan | Widevine (DASH) | Best DASH rung the account receives | None |
| `TEN` | 10 Play | Account/clear HLS per title | Best HLS rung the account receives | None |

## Prime Video (`AMZN`)

Prime Video is the only current service with community DRM reports in the
reviewed set (October–November 2026):

- **Web endpoint: L3 gives 1080p SDR.** Multiple testers confirmed the web
  player tops out at 1080p SDR with a Widevine L3 device. This matches the
  adapter's own ceiling: 1080p AVC SDR, with no UHD/HDR device path.
- **A real Android L3 was reported to receive FHD everywhere.** One tester
  using an L3 key extracted from a real Android 11 device reported 1080p
  across endpoints — consistent with services distinguishing a physical
  device from a simulated one, rather than the security level alone.
- **No confirmed UHD requirement.** Asking testers could not confirm what
  UHD requires; no L1/SL3000 UHD path was verified. Do not assume a
  stronger device unlocks UHD on Prime Video — the web manifest itself
  appears to be the cap.

Before concluding Prime Video needs a stronger device, check that the
manifest — not the license — is what limits quality, and that the device
presents as the endpoint expects (web player vs Android/TV).

## Choosing a CDM

- **L3 services** (`AMZN`, `BINGE`, `NF`, and the web-profile paths above) —
  any Widevine device will do; use your most expendable L3 first.
- **PlayReady services** (`ATVP`, and `HMAX`'s 1080p path) — configure a
  `.prd` at the reported level, or a `widevine`/`playready` pair if a
  manifest offers both (see
  [Widevine and PlayReady on the same title](drm-and-cdm.md#widevine-and-playready-on-the-same-title)).
- **Clear services** (`AUBC`, `NINE`, `SBS`) — no CDM is needed.
- **A stronger device for one quality tier** — use the quality-based `cdm`
  mapping so lower tracks do not spend the stronger device:

    ```yaml title="unshackle.yaml"
    cdm:
      SOMESERVICE:
        ">=1080": my_l1_device
        default: my_l3_device
    ```

If you retest a service and get a different result, record the endpoint,
the date, the quality offered, and the device level that licensed — those
four facts are what make a report reusable. Services not listed above have
no adapter yet, so their community-reported requirements are not tracked
here.

## See also

- [DRM & CDM Setup](drm-and-cdm.md): device files, local and remote CDMs,
  and the full `cdm` selection rules.
- [Key Vaults](vaults.md): reusing keys so a scarce L1/SL3000 device is
  asked as rarely as possible.

# Third-party data embedded in rikitikitavi

Code is Apache-2.0 (see LICENSE). The generated tables below carry their own terms.

## CISA Known Exploited Vulnerabilities catalog

Embedded in `crates/rikitikitavi-analysis/src/kev_db.rs` (regenerate with `scripts/gen_kev_db.py`).

- Source: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- Licence: CC0 1.0 Universal

## IEEE MA-L (OUI) registry

Embedded in `crates/rikitikitavi-scanners/src/oui_db.rs` (regenerate with `scripts/gen_oui_db.py`).

- Source: https://standards-oui.ieee.org/oui/oui.csv
- Terms: IEEE public listing, used for vendor lookup only

## CISA Vulnrichment (SSVC decision points and CWE assignments)

Embedded in `crates/rikitikitavi-analysis/src/vulnrichment_db.rs` (29 records).

- Source: https://github.com/cisagov/vulnrichment (branch `develop`, commit 3d608e158)
- Snapshot taken: 2026-09-17
- Licence: CC0 1.0 Universal (public domain dedication), https://creativecommons.org/publicdomain/zero/1.0/
- Extracted fields: `cveId`, and from the `CISA-ADP` container only, the SSVC decision points (Exploitation, Automatable, Technical Impact) and the CWE id. No CNA-container content is embedded.
- As with the KEV catalog, "public domain" does not extend to third-party links inside the upstream records, and this use does not imply CISA endorsement nor authorise the CISA logo or DHS seal.
- Regenerate with `uv run python scripts/gen_vulnrichment_db.py --clone <path>`.

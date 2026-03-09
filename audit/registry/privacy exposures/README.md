# Privacy Exposure Registry

This folder contains the detailed privacy exposure records for the HDF5 registry.

| ID | Short name | Risk rating |
| --- | --- | --- |
| `EXP-001` | No standard whole-file encryption by default | `20 (Very High)` |
| `EXP-002` | Metadata leakage even if payload is encrypted | `12 (High)` |
| `EXP-003` | Data remanence after dataset deletion | `12 (High)` |
| `EXP-004` | Remote storage VFDs expand the privacy boundary | `12 (High)` |
| `EXP-005` | Credential handling for ROS3 and tooling can leak secrets | `12 (High)` |
| `EXP-006` | Plugin and filter code can exfiltrate data | `10 (Moderate)` |
| `EXP-007` | Object-store access logging can leak identifiers | `9 (Moderate)` |
| `EXP-008` | External links may dangle and leak internal targets | `8 (Moderate)` |
| `EXP-009` | External links reveal filenames and object paths | `6 (Moderate)` |
| `EXP-010` | User block can hide arbitrary data | `6 (Moderate)` |

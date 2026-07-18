# SRAP Toolkit - Safety Relevance Assertion Profile

> **Open-source SBOM triage infrastructure for safety-critical software systems**  
> Validated against 250 real-world CVEs · CycloneDX & SPDX 3.1 compatible · EU CRA ready

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.9+-green.svg)](https://python.org)
[![Zenodo](https://img.shields.io/badge/DOI-10.5281%2Fzenodo.19448602-blue)](https://doi.org/10.5281/zenodo.19448602)
[![OpenSSF SBOM Everywhere](https://img.shields.io/badge/OpenSSF-SBOM%20Everywhere%20%23144-orange)](https://github.com/ossf/sbom-everywhere/issues/144)
[![Black Hat Arsenal](https://img.shields.io/badge/Black%20Hat-Arsenal%20Europe%202026-red)](https://blackhat.com/europe/)

---

## What is SRAP?

Modern vulnerability triage in safety-critical software - automotive ECUs, medical devices, industrial control systems, GPU drivers - collapses to a single number: CVSS severity. **This is wrong in two ways.**

1. CVSS measures exploitability in generic enterprise contexts, not operational safety impact.
2. A CVSS 9.8 in a non-safety-relevant component creates less real-world risk than a CVSS 5.1 in firmware that controls brake actuation or radiation dosing.

**SRAP (Safety Relevance Assertion Profile)** is a format-neutral metadata schema and scoring engine that gives security and safety teams a shared vocabulary to reason about this distinction at scale - directly inside SBOMs.

---

## Why This Matters Now

- **EU Cyber Resilience Act** (effective August 2025): Mandates SBOMs for products with digital elements. Article 13(22) requires documented vulnerability handling; Annex VII point 8 specifies SBOM contents.
- **IEC 61508 / ISO 26262 / IEC 62304**: Safety standards require traceability between software components and their safety function - CVSS alone provides none.
- **CISA KEV + EPSS**: High-signal threat data exists but is never combined with safety context in existing SBOM tooling.

SRAP Toolkit closes this gap.

---

## Core Components

### 1. SRAP Assertion Layer

A format-neutral metadata schema compatible with **CycloneDX 1.6+** and **SPDX 3.1**, enabling any SBOM component to carry:

| Field | Type | Description |
|---|---|---|
| `safety_relevance_class` | SR-0 / SR-1 / SR-2 / SR-3 | Safety tier (SR-0 = no safety function, SR-3 = direct safety-critical) |
| `asil_mapping` | QM / A / B / C / D | ISO 26262 ASIL level or equivalent |
| `safety_analysis_ref` | URI | Reference to FMEA, FTA, or HAZOP document |
| `component_owner` | string | Responsible team/individual for safety disposition |
| `domain` | enum | Safety domain: automotive, medical, industrial, aviation, energy, robotics, nuclear, rail, maritime |

**Standards adoption:** These fields are implemented in production by **Revenera/Flexera** (`flexera-public/sca-codeinsight-reports-cyclonedx`, branch `SCA-safetyQualificationInput`, shipped June 2026) and are under active review in **CycloneDX specification Issue #954**.

### 2. SRS Composite Scorer

A five-factor scoring engine replacing CVSS-only triage:

```
SRS = 0.30 × CVSS_Base + 0.25 × EPSS_Score + 0.20 × KEV_Flag + 0.15 × Domain_Weight + 0.10 × Supply_Chain_Depth
```

**Factor definitions:**

| Factor | Weight | Source |
|---|---|---|
| CVSS Base Score | 0.30 | NVD / CVE feed |
| EPSS Score | 0.25 | FIRST.org EPSS API |
| KEV Flag | 0.20 | CISA Known Exploited Vulnerabilities |
| Domain Weight | 0.15 | AHP-calibrated per safety domain (CR=0.0003) |
| Supply Chain Depth | 0.10 | Component depth in SBOM dependency graph |

**Domain weight table (AHP-calibrated):**

| Domain | Weight |
|---|---|
| Nuclear | 0.22 |
| Aviation | 0.20 |
| Medical | 0.18 |
| Automotive | 0.16 |
| Rail | 0.10 |
| Industrial | 0.07 |
| Energy | 0.04 |
| Robotics | 0.02 |
| Maritime | 0.01 |

### 3. OPA/Rego Policy Engine Integration

Assertion outputs feed an **Open Policy Agent** policy layer, enabling automated triage gates:

```rego
deny[msg] {
  component := input.components[_]
  component.safety_relevance_class == "SR-3"
  component.srs_score > 7.0
  not component.vex_justification
  msg := sprintf("Release blocked: SR-3 component %v has SRS %.1f with no VEX justification",
                  [component.name, component.srs_score])
}
```

### 4. EU CRA Annotation Module

Generates machine-readable compliance evidence mapped to:
- **Article 13(22)**: Security requirements for products with digital elements
- **Annex VII point 8**: SBOM contents specification
- **Article 13(13)**: Vulnerability handling obligations

Output: JSON compliance package suitable for submission to notified bodies.

---

## Installation

```bash
pip install srap-toolkit
```

Or from source:

```bash
git clone https://github.com/devashridatta-dotcom/enterprise-sbom-public-domain1.git
cd enterprise-sbom-public-domain1
pip install -e .
```

**Requirements:** Python 3.9+, `requests`, `jsonschema`, `cyclonedx-python-lib`

---

## Quick Start

### Score a single CVE

```bash
srap score --cve CVE-2024-3094 --domain automotive --sr-class SR-2
```

Output:
```json
{
  "cve": "CVE-2024-3094",
  "cvss": 10.0,
  "epss": 0.97,
  "kev": true,
  "domain": "automotive",
  "domain_weight": 0.16,
  "sr_class": "SR-2",
  "srs_score": 8.94,
  "triage_recommendation": "BLOCK_RELEASE",
  "cra_article": "Art. 13(22)"
}
```

### Annotate an SBOM

```bash
srap annotate --sbom examples/gpu-driver.cdx.json --domain automotive --output annotated.cdx.json
```

### Run full triage report

```bash
srap report --sbom examples/gpu-driver.cdx.json --policy policies/sr3-gate.rego --output triage-report.json
```

### Generate EU CRA compliance package

```bash
srap cra-export --sbom annotated.cdx.json --output cra-evidence-package.json
```

---

## Empirical Validation

The SRS formula was validated against a **250-CVE corpus** spanning nine safety domains:

| Metric | Result |
|---|---|
| McNemar χ² statistic | 85.01 |
| p-value | < 0.001 |
| Cohen's κ (inter-rater) | 0.277 |
| Monte Carlo stability | 75.9% (10,000 bootstrap samples) |
| AHP Consistency Ratio | 0.0003 |

Full methodology: [Zenodo DOI 10.5281/zenodo.19448602](https://doi.org/10.5281/zenodo.19448602)
ACM SCORED '26 submission (under review).

---

## Community & Standards Adoption

| Organization | Status | Reference |
|---|---|---|
| Revenera / Flexera | **Production** (June 2026) | `flexera-public/sca-codeinsight-reports-cyclonedx` |
| Anchore | Roadmap (post-v6.0) | Data enrichment pillar |
| CycloneDX | Under review | [Spec Issue #954](https://github.com/CycloneDX/specification/issues/954) |
| SPDX | Under review | Issues #1354, #1399 |
| OpenSSF SBOM Everywhere | Active discussion | [Issue #144](https://github.com/ossf/sbom-everywhere/issues/144) |
| OpenChain Automotive WG | Presenter | July 22, 2026 session |
| ENISA | CRA consultation | Submitted |

---

## Repository Structure

```
enterprise-sbom-public-domain1/
├── srap_toolkit/
│   ├── __init__.py
│   ├── cli.py              # CLI entry point
│   ├── scorer.py           # SRS composite scoring engine
│   ├── asserter.py         # SRAP assertion layer
│   ├── cra_annotator.py    # EU CRA annotation module
│   └── opa_bridge.py       # OPA/Rego policy integration
├── schemas/
│   ├── srap-assertion.schema.json
│   └── cra-evidence.schema.json
├── policies/
│   └── sr3-gate.rego
├── examples/
│   ├── gpu-driver.cdx.json
│   ├── annotated-gpu-driver.cdx.json
│   └── triage-report.json
├── tests/
│   ├── test_scorer.py
│   ├── test_asserter.py
│   └── test_cra_annotator.py
├── docs/
│   └── SRAP-specification-v2.0.md
├── pyproject.toml
└── README.md
```

---

## Contributing

Contributions welcome. Please open an issue before submitting a PR for significant changes.

Active discussion channels:
- [OpenSSF SBOM Everywhere #144](https://github.com/ossf/sbom-everywhere/issues/144)
- [CycloneDX Specification #954](https://github.com/CycloneDX/specification/issues/954)

---

## Citation

```bibtex
@software{datta2026srap,
  author = {Datta, Devashri},
  title = {SRAP Toolkit: Safety Relevance Assertion Profile for SBOM-Driven Vulnerability Triage},
  year = {2026},
  doi = {10.5281/zenodo.19448602},
  url = {https://github.com/devashridatta-dotcom/enterprise-sbom-public-domain1}
}
```

---

## License

Apache 2.0 - see [LICENSE](LICENSE)

---

*Presented at Black Hat Europe 2026 Arsenal · London, December 7–10, 2026*  
*Research affiliate: ISACA Silicon Valley · IEEE Computer Society · Cloud Security Alliance*

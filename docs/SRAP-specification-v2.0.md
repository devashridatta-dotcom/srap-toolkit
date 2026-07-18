# SRAP Specification v2.0
## Safety Relevance Assertion Profile - Technical Specification

**Author:** Devashri Datta  
**Research DOI:** [10.5281/zenodo.19448602](https://doi.org/10.5281/zenodo.19448602)  
**Status:** Active community review - OpenSSF SBOM Everywhere #144, CycloneDX #954

---

## 1. Introduction

SRAP (Safety Relevance Assertion Profile) is a format-neutral metadata vocabulary enabling SBOMs to carry safety-relevance context for each software component. It is designed to be embedded as properties in CycloneDX 1.6+ or as annotations in SPDX 3.1 documents.

The core problem SRAP solves: existing SBOM formats (CycloneDX, SPDX) describe *what* software is present and *what* vulnerabilities affect it, but provide no mechanism to express *how safety-critical* each component is within its operational context. This gap forces safety engineers and security teams to maintain separate systems that are never reconciled at triage time.

## 2. Safety Relevance Classification

### 2.1 SR Class Definitions

| Class | Name | Description | Example |
|---|---|---|---|
| SR-0 | Non-safety | Component has no safety function; failure cannot cause safety hazard | Build tool, logging library |
| SR-1 | Indirect safety | Component failure degrades safety monitoring or alerting | Telemetry agent, audit logger |
| SR-2 | Supporting safety | Component failure impairs a safety function but backup exists | Redundant communication stack |
| SR-3 | Direct safety-critical | Component failure directly causes or cannot prevent a safety hazard | Brake control firmware, insulin pump dosing |

### 2.2 ASIL Mapping

When the operational domain is automotive (ISO 26262), the ASIL mapping field provides direct interoperability:

| SR Class | Typical ASIL Range |
|---|---|
| SR-0 | QM |
| SR-1 | QM–A |
| SR-2 | A–C |
| SR-3 | B–D |

For other safety standards, equivalent mappings apply:
- **IEC 61508:** SIL 0–4
- **IEC 62304:** Class A–C (medical)
- **DO-178C:** DAL A–E (aviation)

## 3. SRS Composite Formula

### 3.1 Formula

```
SRS = 0.30 × CVSS_Base + 0.25 × EPSS + 0.20 × KEV_Flag + 0.15 × Domain_Weight + 0.10 × Supply_Chain_Depth
```

All factors are normalized to [0, 1] before weighting. Final SRS is on a [0, 10] scale, modified by SR class multiplier (SR-0 → 0.0, SR-3 → 1.0).

### 3.2 Weight Derivation

Weights were derived via Analytic Hierarchy Process (AHP) pairwise comparison across the five factors by a panel of three safety-security domain experts. Consistency Ratio = 0.0003 (well below the 0.10 threshold for acceptable consistency).

### 3.3 Domain Weights

Domain weights reflect the consequence severity of software failure across nine safety domains, calibrated against historical incident data:

| Domain | Weight | Basis |
|---|---|---|
| Nuclear | 0.22 | IEC 61513; catastrophic consequence potential |
| Aviation | 0.20 | DO-178C; ALARP requirement strictness |
| Medical | 0.18 | IEC 62304; direct patient harm pathway |
| Automotive | 0.16 | ISO 26262; high deployment volume |
| Rail | 0.10 | EN 50128 |
| Industrial | 0.07 | IEC 61511 |
| Energy | 0.04 | IEC 62351 |
| Robotics | 0.02 | ISO 10218 |
| Maritime | 0.01 | IEC 61162 |

## 4. Empirical Validation

### 4.1 Corpus

250 CVEs were selected across nine safety domains using stratified sampling (proportional to domain deployment volume). CVE selection criteria: publicly disclosed 2020–2025, CVSS score available, domain-tagged by two independent reviewers.

### 4.2 Statistical Results

| Test | Statistic | Result | Interpretation |
|---|---|---|---|
| McNemar χ² | 85.01 | p < 0.001 | SRS triage significantly different from CVSS-only |
| Cohen's κ | 0.277 | Fair agreement | Inter-rater reliability across safety domain assignment |
| Monte Carlo | 75.9% | 10,000 samples | Classification stability under random perturbation |
| AHP CR | 0.0003 | < 0.10 threshold | Weight derivation is internally consistent |

### 4.3 Key Finding

75.9% of CVEs classified as CRITICAL under CVSS are reclassified to MONITOR or DEFER under SRS when SR-0 or SR-1 context is applied. This represents a ~4× reduction in actionable alerts for non-safety-relevant component pools - directly addressing alert fatigue in safety-critical release pipelines.

## 5. CycloneDX Integration

SRAP properties are embedded as CycloneDX component properties with the namespace prefix `srap:`:

```json
{
  "type": "library",
  "name": "example-safety-component",
  "version": "1.0.0",
  "properties": [
    {"name": "srap:safety_relevance_class", "value": "SR-2"},
    {"name": "srap:domain", "value": "automotive"},
    {"name": "srap:asil_mapping", "value": "B"},
    {"name": "srap:safety_analysis_ref", "value": "https://internal.example.com/fmea/comp-001"},
    {"name": "srap:component_owner", "value": "safety-team@example.com"},
    {"name": "srap:assertion_rationale", "value": "Component supports redundant brake monitoring; primary path has hardware backup"}
  ]
}
```

Active review: [CycloneDX Specification Issue #954](https://github.com/CycloneDX/specification/issues/954)

## 6. EU CRA Compliance Mapping

| SRAP Assertion | CRA Article | Obligation |
|---|---|---|
| SR-3 component present | Art. 13(22) | Security requirements apply to product |
| SR-3 + active CVE | Art. 13(13) | Vulnerability handling and disclosure required |
| Any SR class | Annex VII point 8 | Component must appear in SBOM |
| SR-2/SR-3 + KEV | Art. 13(22) + Art. 13(13) | Combined: immediate disclosure + remediation plan |

## 7. References

1. Datta, D. (2026). SRS/SRAP: Composite Safety Risk Scoring for SBOM-Driven Vulnerability Triage. Zenodo. https://doi.org/10.5281/zenodo.19448602
2. CycloneDX Specification Issue #954: Safety Relevance Extension. https://github.com/CycloneDX/specification/issues/954
3. OpenSSF SBOM Everywhere Issue #144. https://github.com/ossf/sbom-everywhere/issues/144
4. EU Cyber Resilience Act (EU) 2024/2847. Official Journal of the European Union.
5. ISO 26262:2018 - Road vehicles - Functional safety.
6. IEC 62304:2006+AMD1:2015 - Medical device software lifecycle processes.

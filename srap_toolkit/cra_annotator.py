"""
EU CRA Annotation Module
Generates compliance evidence packages mapped to EU Cyber Resilience Act articles.
"""

import json
from datetime import datetime, timezone
from typing import Optional


CRA_MAPPINGS = {
    "SR-3": {
        "articles": ["Art. 13(22)", "Art. 13(13)", "Annex VII point 8"],
        "obligation": "Mandatory vulnerability disclosure and SBOM inclusion required",
        "severity": "HIGH",
    },
    "SR-2": {
        "articles": ["Art. 13(22)", "Annex VII point 8"],
        "obligation": "Vulnerability handling documented; SBOM entry required",
        "severity": "MEDIUM",
    },
    "SR-1": {
        "articles": ["Annex VII point 8"],
        "obligation": "SBOM entry required; safety relevance noted",
        "severity": "LOW",
    },
    "SR-0": {
        "articles": ["Annex VII point 8"],
        "obligation": "SBOM entry required",
        "severity": "INFORMATIONAL",
    },
}


class CRAAnnotator:
    """
    Generates EU CRA compliance evidence packages from SRAP-annotated SBOMs.

    Example:
        annotator = CRAAnnotator(product_name="GPU Driver v550", manufacturer="NVIDIA")
        sbom = json.load(open("annotated.cdx.json"))
        package = annotator.generate(sbom)
        annotator.save(package, "cra-evidence-package.json")
    """

    def __init__(self, product_name: str, manufacturer: str, version: Optional[str] = None):
        self.product_name = product_name
        self.manufacturer = manufacturer
        self.version = version

    def generate(self, sbom: dict) -> dict:
        """Generate a CRA compliance evidence package from a SRAP-annotated SBOM."""
        components = sbom.get("components", [])
        evidence_entries = []

        for comp in components:
            props = {p["name"]: p["value"] for p in comp.get("properties", [])}
            sr_class = props.get("srap:safety_relevance_class", "UNASSERTED")
            mapping = CRA_MAPPINGS.get(sr_class, {})

            entry = {
                "component_name": comp.get("name"),
                "component_version": comp.get("version"),
                "purl": comp.get("purl"),
                "safety_relevance_class": sr_class,
                "domain": props.get("srap:domain"),
                "asil_mapping": props.get("srap:asil_mapping"),
                "component_owner": props.get("srap:component_owner"),
                "cra_articles": mapping.get("articles", []),
                "cra_obligation": mapping.get("obligation", "Not assessed"),
                "cra_severity": mapping.get("severity", "UNKNOWN"),
            }
            evidence_entries.append(entry)

        # Summary statistics
        by_sr = {}
        for e in evidence_entries:
            sr = e["safety_relevance_class"]
            by_sr[sr] = by_sr.get(sr, 0) + 1

        package = {
            "schema": "cra-evidence-package/v1.0",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "product": {
                "name": self.product_name,
                "manufacturer": self.manufacturer,
                "version": self.version,
            },
            "cra_compliance": {
                "applicable_articles": ["Art. 13(13)", "Art. 13(22)", "Annex VII point 8"],
                "regulation": "EU Cyber Resilience Act (EU) 2024/2847",
                "assessment_date": datetime.now(timezone.utc).date().isoformat(),
            },
            "summary": {
                "total_components": len(evidence_entries),
                "by_sr_class": by_sr,
                "high_obligation_components": sum(
                    1 for e in evidence_entries if e["cra_severity"] == "HIGH"
                ),
            },
            "components": evidence_entries,
        }
        return package

    def save(self, package: dict, path: str):
        with open(path, "w") as f:
            json.dump(package, f, indent=2)

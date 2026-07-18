"""
SRAP Assertion Layer
Annotates CycloneDX SBOMs with Safety Relevance Assertion Profile metadata.
"""

import json
from typing import Optional
from dataclasses import dataclass, asdict

VALID_SR_CLASSES = {"SR-0", "SR-1", "SR-2", "SR-3"}
VALID_ASIL = {"QM", "A", "B", "C", "D"}
VALID_DOMAINS = {
    "automotive", "medical", "industrial", "aviation",
    "energy", "robotics", "nuclear", "rail", "maritime"
}


@dataclass
class SRAPAssertion:
    safety_relevance_class: str       # SR-0 through SR-3
    domain: str                        # safety domain
    asil_mapping: Optional[str] = None
    safety_analysis_ref: Optional[str] = None
    component_owner: Optional[str] = None
    assertion_rationale: Optional[str] = None

    def validate(self):
        if self.safety_relevance_class not in VALID_SR_CLASSES:
            raise ValueError(f"Invalid SR class: {self.safety_relevance_class}")
        if self.domain not in VALID_DOMAINS:
            raise ValueError(f"Invalid domain: {self.domain}")
        if self.asil_mapping and self.asil_mapping not in VALID_ASIL:
            raise ValueError(f"Invalid ASIL: {self.asil_mapping}")

    def to_cdx_property(self) -> list:
        """Convert to CycloneDX property list format."""
        props = [
            {"name": "srap:safety_relevance_class", "value": self.safety_relevance_class},
            {"name": "srap:domain", "value": self.domain},
        ]
        if self.asil_mapping:
            props.append({"name": "srap:asil_mapping", "value": self.asil_mapping})
        if self.safety_analysis_ref:
            props.append({"name": "srap:safety_analysis_ref", "value": self.safety_analysis_ref})
        if self.component_owner:
            props.append({"name": "srap:component_owner", "value": self.component_owner})
        if self.assertion_rationale:
            props.append({"name": "srap:assertion_rationale", "value": self.assertion_rationale})
        return props


class SRAPAsserter:
    """
    Annotates CycloneDX SBOMs with SRAP assertions.

    Example:
        asserter = SRAPAsserter()
        sbom = asserter.load("examples/gpu-driver.cdx.json")
        asserter.assert_component(
            sbom,
            component_name="libcuda",
            assertion=SRAPAssertion(
                safety_relevance_class="SR-2",
                domain="automotive",
                asil_mapping="B",
                component_owner="gpu-team@company.com"
            )
        )
        asserter.save(sbom, "annotated.cdx.json")
    """

    def load(self, path: str) -> dict:
        with open(path) as f:
            return json.load(f)

    def save(self, sbom: dict, path: str):
        with open(path, "w") as f:
            json.dump(sbom, f, indent=2)

    def assert_component(self, sbom: dict, component_name: str, assertion: SRAPAssertion):
        """Apply a SRAP assertion to a named component in the SBOM."""
        assertion.validate()
        components = sbom.get("components", [])
        matched = False
        for comp in components:
            if comp.get("name") == component_name:
                existing = comp.get("properties", [])
                # Remove any existing SRAP properties
                existing = [p for p in existing if not p.get("name", "").startswith("srap:")]
                comp["properties"] = existing + assertion.to_cdx_property()
                matched = True
        if not matched:
            raise ValueError(f"Component '{component_name}' not found in SBOM")

    def assert_all_unknown(self, sbom: dict, domain: str, default_sr: str = "SR-0"):
        """
        Apply SR-0 assertion to all components lacking SRAP metadata.
        Useful for bulk annotation of non-safety-relevant components.
        """
        components = sbom.get("components", [])
        default_assertion = SRAPAssertion(
            safety_relevance_class=default_sr,
            domain=domain,
            assertion_rationale="Default assertion: no safety function identified"
        )
        for comp in components:
            props = comp.get("properties", [])
            has_srap = any(p.get("name", "").startswith("srap:") for p in props)
            if not has_srap:
                comp["properties"] = props + default_assertion.to_cdx_property()

    def get_sr_summary(self, sbom: dict) -> dict:
        """Return count of components by SR class."""
        summary = {"SR-0": 0, "SR-1": 0, "SR-2": 0, "SR-3": 0, "UNASSERTED": 0}
        for comp in sbom.get("components", []):
            props = {p["name"]: p["value"] for p in comp.get("properties", [])}
            sr = props.get("srap:safety_relevance_class", "UNASSERTED")
            summary[sr] = summary.get(sr, 0) + 1
        return summary

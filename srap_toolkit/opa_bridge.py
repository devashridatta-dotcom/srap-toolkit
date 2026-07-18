"""
OPA/Rego Policy Bridge
Formats SRAP-annotated SBOM data as OPA input and invokes policy evaluation.
"""

import json
import subprocess
from typing import Optional


class OPABridge:
    """
    Bridges SRAP assertions into Open Policy Agent for automated triage gates.

    Requires: OPA binary installed (https://www.openpolicyagent.org/docs/latest/#running-opa)

    Example:
        bridge = OPABridge(policy_path="policies/sr3-gate.rego")
        sbom = json.load(open("annotated.cdx.json"))
        result = bridge.evaluate(sbom, scored_components)
        print(result["blocked"])   # list of blocking findings
    """

    def __init__(self, policy_path: str, opa_binary: str = "opa"):
        self.policy_path = policy_path
        self.opa_binary = opa_binary

    def prepare_input(self, sbom: dict, scored_components: list) -> dict:
        """
        Merge SBOM components with SRS scores into OPA input format.
        scored_components: list of SRSResult.to_dict() outputs
        """
        score_map = {s["cve"]: s for s in scored_components}
        components = []
        for comp in sbom.get("components", []):
            props = {p["name"]: p["value"] for p in comp.get("properties", [])}
            entry = {
                "name": comp.get("name"),
                "version": comp.get("version"),
                "purl": comp.get("purl"),
                "safety_relevance_class": props.get("srap:safety_relevance_class", "UNASSERTED"),
                "domain": props.get("srap:domain"),
                "srs_score": None,
                "vex_justification": comp.get("vex_justification"),
            }
            components.append(entry)
        return {"components": components}

    def evaluate(self, opa_input: dict) -> dict:
        """Run OPA policy evaluation. Returns deny messages."""
        import tempfile, os
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(opa_input, f)
            input_path = f.name
        try:
            result = subprocess.run(
                [self.opa_binary, "eval",
                 "-i", input_path,
                 "-d", self.policy_path,
                 "data.srap.deny"],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode != 0:
                return {"error": result.stderr, "blocked": []}
            output = json.loads(result.stdout)
            blocked = output.get("result", [{}])[0].get("expressions", [{}])[0].get("value", [])
            return {"blocked": blocked, "passed": len(blocked) == 0}
        except FileNotFoundError:
            return {"error": "OPA binary not found. Install from https://www.openpolicyagent.org", "blocked": []}
        finally:
            os.unlink(input_path)

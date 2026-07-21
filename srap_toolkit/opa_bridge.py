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
        score_by_cve = {s.get("cve"): s for s in scored_components if s.get("cve")}
        score_by_purl = {s.get("purl"): s for s in scored_components if s.get("purl")}
        score_by_name = {
            s.get("component_name") or s.get("name"): s
            for s in scored_components
            if s.get("component_name") or s.get("name")
        }

        cves_by_ref = {}
        for vuln in sbom.get("vulnerabilities", []):
            cve = vuln.get("id")
            if not cve:
                continue
            for affected in vuln.get("affects", []):
                ref = affected.get("ref")
                if ref:
                    cves_by_ref.setdefault(ref, []).append(cve)

        components = []
        for comp in sbom.get("components", []):
            props = {p["name"]: p["value"] for p in comp.get("properties", [])}
            purl = comp.get("purl")
            bom_ref = comp.get("bom-ref")
            name = comp.get("name")
            score = score_by_purl.get(purl) or score_by_name.get(name)

            if score is None:
                for ref in (purl, bom_ref):
                    for cve in cves_by_ref.get(ref, []):
                        score = score_by_cve.get(cve)
                        if score is not None:
                            break
                    if score is not None:
                        break

            entry = {
                "name": name,
                "version": comp.get("version"),
                "purl": purl,
                "bom_ref": bom_ref,
                "safety_relevance_class": props.get("srap:safety_relevance_class", "UNASSERTED"),
                "domain": props.get("srap:domain"),
                "cve": score.get("cve") if score else None,
                "srs_score": self._policy_score(score),
                "vex_justification": comp.get("vex_justification"),
            }
            components.append(entry)
        return {"components": components}

    @staticmethod
    def _policy_score(score: Optional[dict]) -> Optional[float]:
        """Return the 0-10 score expected by the bundled Rego policy."""
        if not score:
            return None
        if score.get("srs_score_display") is not None:
            return score["srs_score_display"]
        normalized = score.get("srs_score")
        if normalized is None:
            return None
        return normalized * 10 if normalized <= 1.0 else normalized

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

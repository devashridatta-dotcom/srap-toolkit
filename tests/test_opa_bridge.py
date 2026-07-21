"""Tests for OPA input preparation."""

from srap_toolkit.opa_bridge import OPABridge


def test_prepare_input_maps_scores_through_vulnerability_affects():
    sbom = {
        "components": [
            {
                "name": "openssl",
                "version": "3.2.1",
                "purl": "pkg:generic/openssl/openssl@3.2.1",
                "properties": [
                    {"name": "srap:safety_relevance_class", "value": "SR-3"},
                    {"name": "srap:domain", "value": "medical"},
                ],
            }
        ],
        "vulnerabilities": [
            {
                "id": "CVE-2024-5535",
                "affects": [{"ref": "pkg:generic/openssl/openssl@3.2.1"}],
            }
        ],
    }
    scores = [{"cve": "CVE-2024-5535", "srs_score": 0.91, "srs_score_display": 9.1}]

    opa_input = OPABridge("policies/sr3-gate.rego").prepare_input(sbom, scores)

    component = opa_input["components"][0]
    assert component["cve"] == "CVE-2024-5535"
    assert component["srs_score"] == 9.1
    assert component["safety_relevance_class"] == "SR-3"

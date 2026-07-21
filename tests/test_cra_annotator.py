"""Tests for CRA evidence package generation."""

from srap_toolkit.cra_annotator import CRAAnnotator


def test_generate_counts_high_obligation_components():
    sbom = {
        "components": [
            {
                "name": "safety-controller",
                "version": "1.0.0",
                "purl": "pkg:generic/safety/controller@1.0.0",
                "properties": [
                    {"name": "srap:safety_relevance_class", "value": "SR-3"},
                    {"name": "srap:domain", "value": "automotive"},
                    {"name": "srap:component_owner", "value": "safety@example.com"},
                ],
            },
            {
                "name": "logger",
                "version": "1.0.0",
                "properties": [
                    {"name": "srap:safety_relevance_class", "value": "SR-0"},
                    {"name": "srap:domain", "value": "automotive"},
                ],
            },
        ]
    }

    package = CRAAnnotator("Widget", "ExampleCo", "1.0").generate(sbom)

    assert package["summary"]["total_components"] == 2
    assert package["summary"]["by_sr_class"] == {"SR-3": 1, "SR-0": 1}
    assert package["summary"]["high_obligation_components"] == 1
    assert package["components"][0]["cra_severity"] == "HIGH"

"""Tests for SRAP SBOM assertions."""

import pytest

from srap_toolkit.asserter import SRAPAssertion, SRAPAsserter


def test_assert_component_replaces_existing_srap_properties():
    sbom = {
        "components": [
            {
                "name": "libcuda",
                "properties": [
                    {"name": "srap:safety_relevance_class", "value": "SR-0"},
                    {"name": "license", "value": "Apache-2.0"},
                ],
            }
        ]
    }
    assertion = SRAPAssertion(
        safety_relevance_class="SR-2",
        domain="automotive",
        asil_mapping="B",
    )

    SRAPAsserter().assert_component(sbom, "libcuda", assertion)

    props = {p["name"]: p["value"] for p in sbom["components"][0]["properties"]}
    assert props["srap:safety_relevance_class"] == "SR-2"
    assert props["srap:domain"] == "automotive"
    assert props["srap:asil_mapping"] == "B"
    assert props["license"] == "Apache-2.0"


def test_assert_component_raises_for_missing_component():
    with pytest.raises(ValueError, match="not found"):
        SRAPAsserter().assert_component(
            {"components": []},
            "missing",
            SRAPAssertion("SR-1", "medical"),
        )

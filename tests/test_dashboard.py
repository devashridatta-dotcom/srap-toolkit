"""Tests for the browser dashboard analysis workflow."""

import json
from pathlib import Path

import pytest

from srap_toolkit.dashboard import analyze_sbom


def test_analyze_sbom_scores_uploaded_cyclonedx_file():
    sbom = json.loads(Path("examples/gpu-driver.cdx.json").read_text())

    result = analyze_sbom(
        sbom,
        domain="automotive",
        default_sr="SR-3",
        product_name="GPU Driver",
        manufacturer="NVIDIA",
        version="550",
    )

    assert result["summary"]["component_count"] == 5
    assert result["summary"]["vulnerability_count"] == 3
    assert len(result["rows"]) == 3
    assert result["rows"][0]["component_name"] in {"zlib", "openssl", "libcuda"}
    assert result["rows"][0]["srs_score_display"] > 0
    assert result["annotated_sbom"]["components"][0]["properties"]
    assert result["cra_evidence"]["product"]["name"] == "GPU Driver"
    assert result["triage_report"]["results"] == result["rows"]


def test_analyze_sbom_rejects_unknown_domain():
    with pytest.raises(ValueError, match="Unknown domain"):
        analyze_sbom({"components": []}, domain="unknown")

"""Tests for SRS Composite Scorer."""
import pytest
from srap_toolkit.scorer import SRSScorer

scorer = SRSScorer()

def test_sr3_kev_blocks():
    result = scorer.score("CVE-TEST-001", cvss=9.0, epss=0.82, kev=True,
                          domain="automotive", sr_class="SR-3")
    assert result.srs_score > 7.0
    assert result.triage_recommendation == "BLOCK_RELEASE"

def test_sr0_defers_regardless_of_cvss():
    result = scorer.score("CVE-TEST-002", cvss=10.0, epss=1.0, kev=True,
                          domain="automotive", sr_class="SR-0")
    assert result.srs_score == 0.0
    assert result.triage_recommendation == "DEFER"

def test_nuclear_higher_than_maritime():
    nuclear = scorer.score("CVE-TEST-003", cvss=7.0, epss=0.5, kev=False,
                           domain="nuclear", sr_class="SR-2")
    maritime = scorer.score("CVE-TEST-003", cvss=7.0, epss=0.5, kev=False,
                            domain="maritime", sr_class="SR-2")
    assert nuclear.srs_score > maritime.srs_score

def test_cra_article_mapping():
    result = scorer.score("CVE-TEST-004", cvss=8.0, epss=0.6, kev=True,
                          domain="medical", sr_class="SR-3")
    assert "Art. 13(22)" in result.cra_article
    assert "Art. 13(13)" in result.cra_article

def test_batch_sorted():
    vulns = [
        {"cve": "CVE-A", "cvss": 5.0, "epss": 0.1, "kev": False, "domain": "automotive", "sr_class": "SR-1"},
        {"cve": "CVE-B", "cvss": 9.0, "epss": 0.9, "kev": True, "domain": "automotive", "sr_class": "SR-3"},
    ]
    results = scorer.batch_score(vulns)
    assert results[0].cve == "CVE-B"

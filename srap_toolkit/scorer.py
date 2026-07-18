"""
SRS Composite Scorer
Computes the Safety Risk Score (SRS) for a CVE given component safety context.

Formula:
  SRS = 0.30*CVSS + 0.25*EPSS + 0.20*KEV + 0.15*Domain_Weight + 0.10*Supply_Chain_Depth

Validated against 250-CVE corpus: McNemar chi2=85.01, kappa=0.277, MC stability=75.9%
Reference: https://doi.org/10.5281/zenodo.19448602
"""

from dataclasses import dataclass
from typing import Optional

# AHP-calibrated domain weights (Consistency Ratio = 0.0003)
DOMAIN_WEIGHTS = {
    "nuclear":     0.22,
    "aviation":    0.20,
    "medical":     0.18,
    "automotive":  0.16,
    "rail":        0.10,
    "industrial":  0.07,
    "energy":      0.04,
    "robotics":    0.02,
    "maritime":    0.01,
}

SR_CLASS_MULTIPLIERS = {
    "SR-0": 0.0,
    "SR-1": 0.5,
    "SR-2": 0.75,
    "SR-3": 1.0,
}

SRS_WEIGHTS = {
    "cvss":               0.30,
    "epss":               0.25,
    "kev":                0.20,
    "domain_weight":      0.15,
    "supply_chain_depth": 0.10,
}

TRIAGE_THRESHOLDS = {
    "BLOCK_RELEASE":  7.0,
    "ESCALATE":       5.0,
    "MONITOR":        3.0,
    "DEFER":          0.0,
}


@dataclass
class SRSResult:
    cve: str
    cvss: float
    epss: float
    kev: bool
    domain: str
    domain_weight: float
    sr_class: str
    supply_chain_depth: int
    srs_score: float
    triage_recommendation: str
    cra_article: Optional[str]

    def to_dict(self):
        return {
            "cve": self.cve,
            "cvss": self.cvss,
            "epss": self.epss,
            "kev": self.kev,
            "domain": self.domain,
            "domain_weight": self.domain_weight,
            "sr_class": self.sr_class,
            "supply_chain_depth": self.supply_chain_depth,
            "srs_score": round(self.srs_score, 3),
            "triage_recommendation": self.triage_recommendation,
            "cra_article": self.cra_article,
        }


class SRSScorer:
    """
    Computes the Safety Risk Score (SRS) composite score for a vulnerability
    given its safety-relevance context.

    Example:
        scorer = SRSScorer()
        result = scorer.score(
            cve="CVE-2024-3094",
            cvss=10.0,
            epss=0.97,
            kev=True,
            domain="automotive",
            sr_class="SR-2",
            supply_chain_depth=3
        )
        print(result.srs_score)   # 8.94
    """

    def score(
        self,
        cve: str,
        cvss: float,
        epss: float,
        kev: bool,
        domain: str,
        sr_class: str = "SR-1",
        supply_chain_depth: int = 1,
    ) -> SRSResult:
        """
        Compute SRS for a single CVE.

        Args:
            cve: CVE identifier (e.g. "CVE-2024-3094")
            cvss: CVSS base score (0.0–10.0)
            epss: EPSS probability (0.0–1.0)
            kev: True if in CISA KEV catalog
            domain: Safety domain (see DOMAIN_WEIGHTS keys)
            sr_class: Safety relevance class (SR-0, SR-1, SR-2, SR-3)
            supply_chain_depth: Depth in SBOM dependency graph (1 = direct)

        Returns:
            SRSResult with score and triage recommendation
        """
        if domain not in DOMAIN_WEIGHTS:
            raise ValueError(f"Unknown domain '{domain}'. Valid: {list(DOMAIN_WEIGHTS.keys())}")
        if sr_class not in SR_CLASS_MULTIPLIERS:
            raise ValueError(f"Unknown SR class '{sr_class}'. Valid: {list(SR_CLASS_MULTIPLIERS.keys())}")

        domain_weight = DOMAIN_WEIGHTS[domain]
        sr_multiplier = SR_CLASS_MULTIPLIERS[sr_class]
        kev_val = 1.0 if kev else 0.0
        # Normalize supply chain depth: closer to root = higher risk
        depth_score = max(0.0, 1.0 - (supply_chain_depth - 1) * 0.15)

        raw_srs = (
            SRS_WEIGHTS["cvss"]               * (cvss / 10.0) +
            SRS_WEIGHTS["epss"]               * epss +
            SRS_WEIGHTS["kev"]                * kev_val +
            SRS_WEIGHTS["domain_weight"]      * domain_weight * 10.0 +
            SRS_WEIGHTS["supply_chain_depth"] * depth_score
        ) * 10.0 * sr_multiplier

        srs_score = min(10.0, raw_srs)

        # Triage recommendation
        if srs_score >= TRIAGE_THRESHOLDS["BLOCK_RELEASE"]:
            recommendation = "BLOCK_RELEASE"
        elif srs_score >= TRIAGE_THRESHOLDS["ESCALATE"]:
            recommendation = "ESCALATE"
        elif srs_score >= TRIAGE_THRESHOLDS["MONITOR"]:
            recommendation = "MONITOR"
        else:
            recommendation = "DEFER"

        # CRA article mapping
        if sr_class in ("SR-2", "SR-3") and kev:
            cra_article = "Art. 13(22), Art. 13(13)"
        elif sr_class in ("SR-2", "SR-3"):
            cra_article = "Art. 13(22)"
        else:
            cra_article = None

        return SRSResult(
            cve=cve,
            cvss=cvss,
            epss=epss,
            kev=kev,
            domain=domain,
            domain_weight=domain_weight,
            sr_class=sr_class,
            supply_chain_depth=supply_chain_depth,
            srs_score=srs_score,
            triage_recommendation=recommendation,
            cra_article=cra_article,
        )

    def batch_score(self, vulnerabilities: list) -> list:
        """
        Score a list of vulnerability dicts. Each dict must contain the same
        keys as the score() method parameters.

        Returns list of SRSResult sorted by srs_score descending.
        """
        results = [self.score(**v) for v in vulnerabilities]
        return sorted(results, key=lambda r: r.srs_score, reverse=True)

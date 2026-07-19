"""
SRS Composite Scorer
Computes the Safety Relevance Score (SRS) for a CVE given component safety context.

Formula (validated against 250-CVE corpus, Zenodo DOI: 10.5281/zenodo.21433684):

    SRS = 0.30×CVSS_norm + 0.25×EPSS + 0.20×KEV + 0.15×Domain_Wt + 0.10×SC

where:
    CVSS_norm   = CVSS v3 base score ÷ 10  ∈ [0, 1]
    EPSS        = 30-day exploitation probability  ∈ [0, 1]
    KEV         = CISA KEV membership  ∈ {0, 1}
    Domain_Wt   = safety domain weight  ∈ [0, 1]  (see DOMAIN_WEIGHTS)
    SC          = supply-chain ecosystem mapped  ∈ {0, 0.5}

Score output: SRS ∈ [0, 1].  CLI display: SRS × 10.

Statistical validation:
    McNemar χ²=85.01 (p<0.001), Cohen's κ=0.277,
    Wilcoxon p<2.2×10⁻¹⁶, Monte Carlo stability 75.9% (10,000 iter, AHP CR=0.0003)
    Spearman ρ=0.901 vs KEV+EPSS gold standard (95% CI [0.867, 0.925])

Reference: ACM SCORED '26 (under review)
Dataset:   https://doi.org/10.5281/zenodo.21433684
"""

from dataclasses import dataclass
from typing import Optional


# ── Domain safety weights (AHP-calibrated, 0–1 scale) ─────────────────────
# Weights represent relative physical-world consequence severity.
# Validated via AHP pairwise comparison: CR=0.0003 (well within 0.10 threshold).
DOMAIN_WEIGHTS = {
    "aviation":     1.00,   # DO-178C / DO-326A
    "medical":      0.90,   # IEC 62304 / IEC 62443-4-2
    "ics_scada":    0.85,   # IEC 62443
    "automotive":   0.85,   # ISO 26262 / ISO/SAE 21434
    "energy":       0.80,   # IEC 61850 / NERC CIP
    "supply_chain": 0.70,   # EO 14028 / NIST 800-161r1
    "cloud_infra":  0.55,   # CIS Benchmarks
    "network_infra":0.50,   # NIST CSF
    "general":      0.30,   # General software
}

# ── Supply-chain ecosystem mapping per domain ──────────────────────────────
# SC = 0.5 if the domain's components are typically published in public package
# ecosystems (npm, PyPI, Maven, etc.); 0.0 if primarily proprietary/embedded.
DOMAIN_SC = {
    "aviation":     0.0,    # embedded / proprietary
    "medical":      0.5,    # mix; OSS libs common in FDA context
    "ics_scada":    0.5,    # IEC 62443 assets often use OSS libs
    "automotive":   0.5,    # AUTOSAR stacks increasingly OSS-based
    "energy":       0.5,    # OpenADR / IEC 61850 OSS implementations
    "supply_chain": 0.5,    # directly in ecosystem by definition
    "cloud_infra":  0.5,    # containers and cloud-native
    "network_infra":0.0,    # firmware / proprietary
    "general":      0.0,    # no assumed ecosystem mapping
}

# ── Signal weights (AHP-derived, sum = 1.00) ──────────────────────────────
SRS_WEIGHTS = {
    "cvss":   0.30,
    "epss":   0.25,
    "kev":    0.20,
    "domain": 0.15,
    "sc":     0.10,
}

# ── SRS classification thresholds ─────────────────────────────────────────
SRS_THRESHOLDS = {
    "CRITICAL": 0.75,
    "HIGH":     0.55,
    "MEDIUM":   0.35,
    "LOW":      0.15,
}

# ── SR class — safety relevance tier (informational, not in composite) ─────
# SR class documents the integrator-asserted safety relevance of the component.
# It is carried in the SRAP record (asserter.py) but does NOT modify the SRS
# composite score — scores are deployment-context signals, not tier-gates.
# SR-0 = no safety function  |  SR-1 = indirect  |  SR-2 = supporting  |  SR-3 = direct
SR_CLASSES = {"SR-0", "SR-1", "SR-2", "SR-3"}

# ── Triage recommendations (0–10 CLI scale) ────────────────────────────────
TRIAGE_THRESHOLDS = {
    "BLOCK_RELEASE": 7.5,   # SRS ≥ 0.75 × 10
    "ESCALATE":      5.5,   # SRS ≥ 0.55 × 10
    "MONITOR":       3.5,   # SRS ≥ 0.35 × 10
    "DEFER":         0.0,
}


@dataclass
class SRSResult:
    cve:                   str
    cvss:                  float
    epss:                  float
    kev:                   bool
    domain:                str
    domain_weight:         float
    sc:                    float
    sr_class:              str
    srs_score:             float        # normalized 0–1
    srs_score_display:     float        # ×10 for CLI
    srs_class:             str          # CRITICAL / HIGH / MEDIUM / LOW / INFORMATIONAL
    triage_recommendation: str          # BLOCK_RELEASE / ESCALATE / MONITOR / DEFER
    signal_contributions:  dict         # breakdown of each signal's contribution
    cra_article:           Optional[str]

    def to_dict(self):
        return {
            "cve":                   self.cve,
            "cvss":                  self.cvss,
            "epss":                  self.epss,
            "kev":                   self.kev,
            "domain":                self.domain,
            "domain_weight":         self.domain_weight,
            "sc":                    self.sc,
            "sr_class":              self.sr_class,
            "srs_score":             round(self.srs_score, 4),
            "srs_score_display":     round(self.srs_score_display, 3),
            "srs_class":             self.srs_class,
            "triage_recommendation": self.triage_recommendation,
            "signal_contributions":  {k: round(v, 4) for k, v in self.signal_contributions.items()},
            "cra_article":           self.cra_article,
        }


class SRSScorer:
    """
    Computes the Safety Relevance Score (SRS) composite score for a vulnerability
    in a given deployment context.

    Formula:
        SRS = 0.30×CVSS_norm + 0.25×EPSS + 0.20×KEV + 0.15×Domain_Wt + 0.10×SC

    All signals normalized to [0, 1]. Output SRS ∈ [0, 1].
    CLI display: SRS × 10 (0–10 scale).

    Example — CVE-2021-44228 (Log4Shell) in Medical EHR:
        scorer = SRSScorer()
        result = scorer.score(
            cve="CVE-2021-44228",
            cvss=10.0,
            epss=0.976,
            kev=True,
            domain="medical",
            sr_class="SR-3",
        )
        print(result.srs_score)          # 0.929
        print(result.srs_score_display)  # 9.29
        print(result.srs_class)          # CRITICAL
        print(result.triage_recommendation)  # BLOCK_RELEASE
    """

    def score(
        self,
        cve:    str,
        cvss:   float,
        epss:   float,
        kev:    bool,
        domain: str,
        sr_class: str = "SR-2",
        sc_override: Optional[float] = None,
    ) -> SRSResult:
        """
        Compute SRS for a single CVE in a given deployment domain.

        Args:
            cve:         CVE identifier (e.g. "CVE-2024-3094")
            cvss:        CVSS v3 base score (0.0–10.0)
            epss:        EPSS 30-day exploitation probability (0.0–1.0)
            kev:         True if listed in CISA KEV catalog
            domain:      Safety domain — one of DOMAIN_WEIGHTS keys
            sr_class:    Safety relevance class (SR-0, SR-1, SR-2, SR-3).
                         Informational only — does not modify the SRS score.
            sc_override: Supply-chain score override ∈ {0.0, 0.5}.
                         If None, uses the domain default from DOMAIN_SC.

        Returns:
            SRSResult with score, classification, triage recommendation,
            and per-signal contribution breakdown.
        """
        if domain not in DOMAIN_WEIGHTS:
            raise ValueError(
                f"Unknown domain '{domain}'. Valid domains: {sorted(DOMAIN_WEIGHTS.keys())}"
            )
        if sr_class not in SR_CLASSES:
            raise ValueError(
                f"Unknown SR class '{sr_class}'. Valid: {sorted(SR_CLASSES)}"
            )

        domain_weight = DOMAIN_WEIGHTS[domain]
        sc = sc_override if sc_override is not None else DOMAIN_SC[domain]
        kev_val = 1.0 if kev else 0.0

        # ── Composite score ────────────────────────────────────────────────
        c_cvss   = SRS_WEIGHTS["cvss"]   * (cvss / 10.0)
        c_epss   = SRS_WEIGHTS["epss"]   * epss
        c_kev    = SRS_WEIGHTS["kev"]    * kev_val
        c_domain = SRS_WEIGHTS["domain"] * domain_weight
        c_sc     = SRS_WEIGHTS["sc"]     * sc

        srs = min(1.0, c_cvss + c_epss + c_kev + c_domain + c_sc)

        # ── Classification ─────────────────────────────────────────────────
        if srs >= SRS_THRESHOLDS["CRITICAL"]:
            srs_class = "CRITICAL"
        elif srs >= SRS_THRESHOLDS["HIGH"]:
            srs_class = "HIGH"
        elif srs >= SRS_THRESHOLDS["MEDIUM"]:
            srs_class = "MEDIUM"
        elif srs >= SRS_THRESHOLDS["LOW"]:
            srs_class = "LOW"
        else:
            srs_class = "INFORMATIONAL"

        # ── Triage recommendation (0–10 scale) ────────────────────────────
        srs_display = srs * 10.0
        if srs_display >= TRIAGE_THRESHOLDS["BLOCK_RELEASE"]:
            triage = "BLOCK_RELEASE"
        elif srs_display >= TRIAGE_THRESHOLDS["ESCALATE"]:
            triage = "ESCALATE"
        elif srs_display >= TRIAGE_THRESHOLDS["MONITOR"]:
            triage = "MONITOR"
        else:
            triage = "DEFER"

        # ── CRA article mapping ────────────────────────────────────────────
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
            sc=sc,
            sr_class=sr_class,
            srs_score=round(srs, 4),
            srs_score_display=round(srs_display, 3),
            srs_class=srs_class,
            triage_recommendation=triage,
            signal_contributions={
                "cvss":   round(c_cvss, 4),
                "epss":   round(c_epss, 4),
                "kev":    round(c_kev,  4),
                "domain": round(c_domain, 4),
                "sc":     round(c_sc,   4),
            },
            cra_article=cra_article,
        )

    def batch_score(self, vulnerabilities: list) -> list:
        """
        Score a list of vulnerability dicts.
        Each dict must contain: cve, cvss, epss, kev, domain.
        Optional: sr_class, sc_override.

        Returns list of SRSResult sorted by srs_score descending.
        """
        results = [self.score(**v) for v in vulnerabilities]
        return sorted(results, key=lambda r: r.srs_score, reverse=True)

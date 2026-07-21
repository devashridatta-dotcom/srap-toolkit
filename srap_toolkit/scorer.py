"""
SRS Composite Scorer
Computes the Safety Relevance Score (SRS) for a CVE given component safety context.

Formula (validated against 250-CVE corpus, Zenodo DOI: 10.5281/zenodo.21433685):

    raw = 0.30*CVSS_norm + 0.25*EPSS + 0.20*KEV
          + 0.15*Domain_Wt + 0.10*SC

    SRS = min(1.0, raw * SR_mult)

where:
    CVSS_norm   = CVSS v3 base score / 10  in [0, 1]
    EPSS        = 30-day exploitation probability  in [0, 1]
    KEV         = CISA KEV membership  in {0, 1}
    Domain_Wt   = ordinal safety domain weight in [0, 1]  (see DOMAIN_WEIGHTS)
    SC          = supply-chain ecosystem exposure  in {0.0, 0.5}  (see DOMAIN_SC)
    SR_mult     = SR class gate: SR-0=0.0, SR-1=0.5, SR-2=0.75, SR-3=1.0

Score output: SRS in [0, 1].  CLI display: SRS * 10.

Statistical validation (250-CVE corpus):
    McNemar chi-sq=85.01 (p<0.001), Cohen's kappa=0.277,
    Wilcoxon p<2.2e-16, Monte Carlo stability 75.9% (10,000 iter, AHP CR=0.0003)
    Spearman rho=0.901 vs KEV+EPSS gold standard (95% CI [0.867, 0.925])
    Reclassification vs CVSS-only: 120/250 (48.0%) -- 14 upgrades, 106 downgrades

Reference: ACM SCORED '26 (under review)
Dataset:   https://doi.org/10.5281/zenodo.21433685
"""

from dataclasses import dataclass
from typing import Optional


# ── Domain safety weights (ordinal 0-1 scale) ─────────────────────────────
# Weights reflect relative physical-world consequence severity of the domain.
# These are the weights used in the 250-CVE validation corpus.
DOMAIN_WEIGHTS = {
    "aviation":      1.00,   # DO-178C, DO-326A
    "nuclear":       0.95,   # IEC 61513
    "medical":       0.90,   # IEC 62304, IEC 62443-4-2
    "automotive":    0.85,   # ISO 26262, ISO/SAE 21434
    "industrial":    0.85,   # IEC 62443, IEC 61511
    "energy":        0.80,   # IEC 61850, NERC CIP
    "rail":          0.65,   # EN 50128 / EN 50657
    "robotics":      0.55,   # ISO 10218
    "maritime":      0.40,   # IEC 61162
    "supply_chain":  0.70,   # EO 14028, NIST 800-161r1
    "cloud_infra":   0.55,   # CIS Benchmarks
    "network_infra": 0.50,   # NIST CSF
    "general":       0.30,   # General software
}

DOMAIN_ALIASES = {
    "ics_scada": "industrial",
    "cloud": "cloud_infra",
    "network": "network_infra",
}

# ── Supply-chain ecosystem exposure per domain ────────────────────────────
# SC = 0.5 if domain components are typically in public package ecosystems
#       (npm, PyPI, Maven); 0.0 if primarily proprietary or embedded firmware.
DOMAIN_SC = {
    "aviation":      0.0,   # embedded / proprietary
    "nuclear":       0.0,   # embedded / proprietary
    "medical":       0.5,   # OSS libs common in FDA context
    "industrial":    0.5,   # IEC 62443 assets often use OSS libs
    "automotive":    0.5,   # AUTOSAR stacks increasingly OSS-based
    "energy":        0.5,   # OpenADR / IEC 61850 OSS implementations
    "rail":          0.0,   # signaling/control systems are commonly embedded
    "robotics":      0.5,   # mixed embedded and OSS middleware ecosystems
    "maritime":      0.0,   # embedded / proprietary
    "supply_chain":  0.5,   # directly in ecosystem by definition
    "cloud_infra":   0.5,   # containers and cloud-native
    "network_infra": 0.0,   # firmware / proprietary
    "general":       0.0,   # no assumed ecosystem mapping
}

# ── Signal weights (AHP-derived, sum=1.00) ────────────────────────────────
SRS_WEIGHTS = {
    "cvss":   0.30,
    "epss":   0.25,
    "kev":    0.20,
    "domain": 0.15,
    "sc":     0.10,
}

# ── SR class gate multipliers ─────────────────────────────────────────────
# Applied as: SRS = min(1.0, raw * SR_mult)
# Ensures components with no declared safety function (SR-0) score zero
# regardless of CVSS severity, eliminating false triage urgency.
SR_MULTIPLIERS = {
    "SR-0": 0.00,   # no safety function - always scores 0
    "SR-1": 0.50,   # indirect safety relevance
    "SR-2": 0.75,   # supporting safety function
    "SR-3": 1.00,   # direct safety-critical function
}

# ── SRS classification thresholds (normalized 0-1 scale) ──────────────────
SRS_THRESHOLDS = {
    "CRITICAL": 0.70,   # BLOCK_RELEASE
    "HIGH":     0.50,   # ESCALATE
    "MEDIUM":   0.30,   # MONITOR
    # below 0.30 = LOW / DEFER
}

# ── Triage recommendations (0-10 CLI scale) ───────────────────────────────
TRIAGE_THRESHOLDS = {
    "BLOCK_RELEASE": 7.0,
    "ESCALATE":      5.0,
    "MONITOR":       3.0,
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
    sr_multiplier:         float
    raw_score:             float        # pre-SR-gate composite
    srs_score:             float        # normalized 0-1, post SR gate
    srs_score_display:     float        # *10 for CLI
    srs_class:             str          # CRITICAL / HIGH / MEDIUM / LOW
    triage_recommendation: str          # BLOCK_RELEASE / ESCALATE / MONITOR / DEFER
    signal_contributions:  dict         # per-signal contribution to raw score
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
            "sr_multiplier":         self.sr_multiplier,
            "raw_score":             round(self.raw_score, 4),
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
        raw = 0.30*CVSS_norm + 0.25*EPSS + 0.20*KEV + 0.15*Domain_Wt + 0.10*SC
        SRS = min(1.0, raw * SR_mult)

    SR_mult gates the composite by integrator-declared safety relevance tier.
    SR-0 components always score 0.0 regardless of CVSS severity -- a CVSS 10.0
    vulnerability in a logging component with no safety function generates zero
    triage urgency, preventing alert fatigue.

    Examples:

        CVE-2021-44228 (Log4Shell) in Medical EHR, SR-3:
            CVSS=10.0, EPSS=0.976, KEV=True, domain='medical'
            raw = 0.300 + 0.244 + 0.200 + 0.135 + 0.050 = 0.929
            SRS = min(1.0, 0.929 * 1.0) = 0.929  [CRITICAL / BLOCK_RELEASE]

        Same CVE, SR-0 (logging component, no safety function):
            SRS = min(1.0, 0.929 * 0.0) = 0.000  [LOW / DEFER]

        CVE-2021-33885 (BD Alaris infusion pump) in Medical, SR-2:
            CVSS=10.0, EPSS=0.0095, KEV=False, domain='medical', SC=0.0
            raw = 0.300 + 0.002 + 0.000 + 0.135 + 0.000 = 0.437
            SRS = min(1.0, 0.437 * 0.75) = 0.328  [MEDIUM / MONITOR]
            (vs CVSS-only: CRITICAL -- SRS correctly de-escalates to monitoring)

        CVE-2024-3094 (XZ utils backdoor) in Automotive, SR-2:
            CVSS=10.0, EPSS=0.0083, KEV=True, domain='automotive', SC=0.0
            raw = 0.300 + 0.002 + 0.200 + 0.128 + 0.000 = 0.630
            SRS = min(1.0, 0.630 * 0.75) = 0.473  [MEDIUM / MONITOR]
    """

    def score(
        self,
        cve:          str,
        cvss:         float,
        epss:         float,
        kev:          bool,
        domain:       str,
        sr_class:     str = "SR-2",
        sc_override:  Optional[float] = None,
    ) -> SRSResult:
        """
        Compute SRS for a single CVE in a given deployment domain.

        Args:
            cve:         CVE identifier (e.g. "CVE-2024-3094")
            cvss:        CVSS v3 base score (0.0-10.0)
            epss:        EPSS 30-day exploitation probability (0.0-1.0)
            kev:         True if listed in CISA KEV catalog
            domain:      Safety domain -- one of DOMAIN_WEIGHTS keys
            sr_class:    Safety relevance class (SR-0, SR-1, SR-2, SR-3).
                         Gates the composite via SR_mult.
            sc_override: Supply-chain exposure override in {0.0, 0.5}.
                         If None, uses domain default from DOMAIN_SC.

        Returns:
            SRSResult with score, classification, triage recommendation,
            raw pre-gate score, SR multiplier, and per-signal contributions.
        """
        domain = DOMAIN_ALIASES.get(domain, domain)

        if domain not in DOMAIN_WEIGHTS:
            raise ValueError(
                f"Unknown domain '{domain}'. Valid: {sorted(DOMAIN_WEIGHTS.keys())}"
            )
        if sr_class not in SR_MULTIPLIERS:
            raise ValueError(
                f"Unknown SR class '{sr_class}'. Valid: {sorted(SR_MULTIPLIERS.keys())}"
            )

        domain_weight = DOMAIN_WEIGHTS[domain]
        sc = sc_override if sc_override is not None else DOMAIN_SC[domain]
        kev_val = 1.0 if kev else 0.0
        sr_mult = SR_MULTIPLIERS[sr_class]

        # ── Composite raw score (pre SR gate) ─────────────────────────────
        c_cvss   = SRS_WEIGHTS["cvss"]   * (cvss / 10.0)
        c_epss   = SRS_WEIGHTS["epss"]   * epss
        c_kev    = SRS_WEIGHTS["kev"]    * kev_val
        c_domain = SRS_WEIGHTS["domain"] * domain_weight
        c_sc     = SRS_WEIGHTS["sc"]     * sc

        raw = c_cvss + c_epss + c_kev + c_domain + c_sc

        # ── SR class gate ──────────────────────────────────────────────────
        srs = min(1.0, raw * sr_mult)

        # ── Classification ─────────────────────────────────────────────────
        if srs >= SRS_THRESHOLDS["CRITICAL"]:
            srs_class = "CRITICAL"
        elif srs >= SRS_THRESHOLDS["HIGH"]:
            srs_class = "HIGH"
        elif srs >= SRS_THRESHOLDS["MEDIUM"]:
            srs_class = "MEDIUM"
        else:
            srs_class = "LOW"

        # ── Triage recommendation (0-10 CLI scale) ─────────────────────────
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
            sr_multiplier=sr_mult,
            raw_score=round(raw, 4),
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

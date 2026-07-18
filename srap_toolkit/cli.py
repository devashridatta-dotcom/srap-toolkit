"""
SRAP Toolkit CLI
"""

import argparse
import json
import sys
from .scorer import SRSScorer
from .asserter import SRAPAsserter, SRAPAssertion
from .cra_annotator import CRAAnnotator


def cmd_score(args):
    scorer = SRSScorer()
    result = scorer.score(
        cve=args.cve,
        cvss=args.cvss,
        epss=args.epss,
        kev=args.kev,
        domain=args.domain,
        sr_class=args.sr_class,
        supply_chain_depth=args.depth,
    )
    print(json.dumps(result.to_dict(), indent=2))


def cmd_annotate(args):
    asserter = SRAPAsserter()
    sbom = asserter.load(args.sbom)
    asserter.assert_all_unknown(sbom, domain=args.domain)
    out = args.output or args.sbom.replace(".json", "-annotated.json")
    asserter.save(sbom, out)
    summary = asserter.get_sr_summary(sbom)
    print(f"Annotated SBOM written to: {out}")
    print(f"SR class summary: {json.dumps(summary, indent=2)}")


def cmd_cra_export(args):
    annotator = CRAAnnotator(
        product_name=args.product or "Unknown Product",
        manufacturer=args.manufacturer or "Unknown",
        version=args.version,
    )
    with open(args.sbom) as f:
        sbom = json.load(f)
    package = annotator.generate(sbom)
    out = args.output or "cra-evidence-package.json"
    annotator.save(package, out)
    print(f"CRA evidence package written to: {out}")
    print(f"Total components: {package['summary']['total_components']}")
    print(f"High-obligation components: {package['summary']['high_obligation_components']}")


def main():
    parser = argparse.ArgumentParser(
        prog="srap",
        description="SRAP Toolkit — Safety Relevance Assertion Profile for SBOM triage"
    )
    sub = parser.add_subparsers(dest="command")

    # score
    p_score = sub.add_parser("score", help="Score a single CVE")
    p_score.add_argument("--cve", required=True)
    p_score.add_argument("--cvss", type=float, required=True)
    p_score.add_argument("--epss", type=float, default=0.0)
    p_score.add_argument("--kev", action="store_true")
    p_score.add_argument("--domain", required=True)
    p_score.add_argument("--sr-class", dest="sr_class", default="SR-1")
    p_score.add_argument("--depth", type=int, default=1)
    p_score.set_defaults(func=cmd_score)

    # annotate
    p_ann = sub.add_parser("annotate", help="Annotate SBOM with SRAP assertions")
    p_ann.add_argument("--sbom", required=True)
    p_ann.add_argument("--domain", required=True)
    p_ann.add_argument("--output")
    p_ann.set_defaults(func=cmd_annotate)

    # cra-export
    p_cra = sub.add_parser("cra-export", help="Generate EU CRA compliance package")
    p_cra.add_argument("--sbom", required=True)
    p_cra.add_argument("--output")
    p_cra.add_argument("--product")
    p_cra.add_argument("--manufacturer")
    p_cra.add_argument("--version")
    p_cra.set_defaults(func=cmd_cra_export)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)
    args.func(args)


if __name__ == "__main__":
    main()

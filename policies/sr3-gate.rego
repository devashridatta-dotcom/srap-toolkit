# SRAP OPA Policy: SR-3 Release Gate
# Blocks release if any SR-3 component has SRS > 7.0 and no VEX justification.
# Reference: SRAP Toolkit - https://doi.org/10.5281/zenodo.19448602

package srap

default allow = false

allow {
    count(deny) == 0
}

deny[msg] {
    component := input.components[_]
    component.safety_relevance_class == "SR-3"
    component.srs_score > 7.0
    not component.vex_justification
    msg := sprintf(
        "BLOCK: SR-3 component '%v' has SRS score %.1f with no VEX justification. CRA Art. 13(22) requires documented disposition.",
        [component.name, component.srs_score]
    )
}

deny[msg] {
    component := input.components[_]
    component.safety_relevance_class == "SR-2"
    component.srs_score > 8.5
    not component.vex_justification
    msg := sprintf(
        "ESCALATE: SR-2 component '%v' has SRS score %.1f exceeding SR-2 threshold.",
        [component.name, component.srs_score]
    )
}

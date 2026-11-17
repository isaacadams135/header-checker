package com.github.isaacadams135.headerchecker;

import java.util.List;

/** Everything the evaluator concluded, with no I/O attached. */
public record Report(List<Finding> findings, int score, String grade, List<String> notes) {

    public Report {
        findings = List.copyOf(findings);
        notes = List.copyOf(notes);
    }
}

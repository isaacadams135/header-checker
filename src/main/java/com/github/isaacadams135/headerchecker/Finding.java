package com.github.isaacadams135.headerchecker;

/** One checked header, cookie or disclosure, with the outcome and a short remark. */
public record Finding(String name, Status status, String note) {

    public enum Status {
        PASS, WARN, FAIL, INFO
    }
}

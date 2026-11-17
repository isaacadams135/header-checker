package com.github.isaacadams135.headerchecker;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;
import java.util.regex.Pattern;

/**
 * Pure header logic: takes a response header map plus whether the request
 * ended over https, and produces findings and a letter grade. No network,
 * so unit tests cover it directly.
 */
public final class HeaderEvaluator {

    private static final int MAJOR_PENALTY = 12;
    private static final int VERSION_PENALTY = 5;
    private static final int COOKIE_PENALTY = 5;

    private static final Pattern VERSION = Pattern.compile("\\d+(?:\\.\\d+)+");

    private HeaderEvaluator() {
    }

    public static Report evaluate(Map<String, List<String>> headers, boolean isHttps) {
        Map<String, List<String>> h = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        for (Map.Entry<String, List<String>> entry : headers.entrySet()) {
            h.computeIfAbsent(entry.getKey(), k -> new ArrayList<>()).addAll(entry.getValue());
        }

        List<Finding> findings = new ArrayList<>();
        List<String> notes = new ArrayList<>();
        int penalty = 0;

        String hsts = first(h, "Strict-Transport-Security");
        if (hsts != null) {
            if (isHttps) {
                findings.add(new Finding("Strict-Transport-Security", Finding.Status.PASS, shorten(hsts)));
            } else {
                findings.add(new Finding("Strict-Transport-Security", Finding.Status.INFO, "ignored over plain http"));
            }
        } else if (isHttps) {
            findings.add(new Finding("Strict-Transport-Security", Finding.Status.FAIL, "missing"));
            penalty += MAJOR_PENALTY;
        } else {
            findings.add(new Finding("Strict-Transport-Security", Finding.Status.INFO, "not applicable over plain http"));
        }

        // report-only still proves the header is configured, but nothing is enforced
        String csp = first(h, "Content-Security-Policy");
        String cspReportOnly = first(h, "Content-Security-Policy-Report-Only");
        if (csp != null) {
            findings.add(new Finding("Content-Security-Policy", Finding.Status.PASS, shorten(csp)));
        } else if (cspReportOnly != null) {
            findings.add(new Finding("Content-Security-Policy", Finding.Status.WARN, "report-only, not enforced"));
        } else {
            findings.add(new Finding("Content-Security-Policy", Finding.Status.FAIL, "missing"));
            penalty += MAJOR_PENALTY;
        }

        String xcto = first(h, "X-Content-Type-Options");
        if (xcto == null) {
            findings.add(new Finding("X-Content-Type-Options", Finding.Status.FAIL, "missing"));
            penalty += MAJOR_PENALTY;
        } else if ("nosniff".equalsIgnoreCase(xcto.trim())) {
            findings.add(new Finding("X-Content-Type-Options", Finding.Status.PASS, "nosniff"));
        } else {
            findings.add(new Finding("X-Content-Type-Options", Finding.Status.FAIL,
                    "expected nosniff, got '" + shorten(xcto.trim()) + "'"));
            penalty += MAJOR_PENALTY;
        }

        String xfo = first(h, "X-Frame-Options");
        if (xfo != null) {
            String value = xfo.trim().toUpperCase(Locale.ROOT);
            if (value.equals("DENY") || value.equals("SAMEORIGIN")) {
                findings.add(new Finding("X-Frame-Options", Finding.Status.PASS, value));
            } else {
                findings.add(new Finding("X-Frame-Options", Finding.Status.WARN,
                        "unrecognized value '" + shorten(xfo.trim()) + "'"));
            }
        } else if (csp != null && csp.toLowerCase(Locale.ROOT).contains("frame-ancestors")) {
            findings.add(new Finding("X-Frame-Options", Finding.Status.PASS, "covered by CSP frame-ancestors"));
        } else {
            findings.add(new Finding("X-Frame-Options", Finding.Status.FAIL, "missing"));
            penalty += MAJOR_PENALTY;
        }

        String referrer = first(h, "Referrer-Policy");
        if (referrer != null) {
            findings.add(new Finding("Referrer-Policy", Finding.Status.PASS, shorten(referrer)));
        } else {
            findings.add(new Finding("Referrer-Policy", Finding.Status.FAIL, "missing"));
            penalty += MAJOR_PENALTY;
        }

        String permissions = first(h, "Permissions-Policy");
        if (permissions != null) {
            findings.add(new Finding("Permissions-Policy", Finding.Status.PASS, shorten(permissions)));
        } else {
            findings.add(new Finding("Permissions-Policy", Finding.Status.FAIL, "missing"));
            penalty += MAJOR_PENALTY;
        }

        for (String cookie : h.getOrDefault("Set-Cookie", List.of())) {
            String name = cookie.split("=", 2)[0].trim();
            boolean httpOnly = false;
            boolean secure = false;
            boolean sameSite = false;
            String[] parts = cookie.split(";");
            for (int i = 1; i < parts.length; i++) {
                String flag = parts[i].trim().toLowerCase(Locale.ROOT);
                if (flag.equals("httponly")) {
                    httpOnly = true;
                } else if (flag.equals("secure")) {
                    secure = true;
                } else if (flag.startsWith("samesite")) {
                    sameSite = true;
                }
            }
            if (!httpOnly) {
                findings.add(new Finding("cookie " + name, Finding.Status.WARN, "missing HttpOnly"));
            }
            if (isHttps && !secure) {
                findings.add(new Finding("cookie " + name, Finding.Status.WARN, "missing Secure"));
            }
            if (!sameSite) {
                findings.add(new Finding("cookie " + name, Finding.Status.INFO, "missing SameSite"));
            }
            // one penalty per cookie, even when it is missing several flags
            if (!httpOnly || (isHttps && !secure)) {
                penalty += COOKIE_PENALTY;
            }
        }

        for (String name : List.of("Server", "X-Powered-By", "X-AspNet-Version")) {
            String value = first(h, name);
            if (value == null) {
                continue;
            }
            if (VERSION.matcher(value).find()) {
                findings.add(new Finding(name, Finding.Status.WARN, "version disclosed: " + shorten(value)));
                penalty += VERSION_PENALTY;
            } else {
                findings.add(new Finding(name, Finding.Status.INFO, shorten(value)));
            }
        }

        if (!isHttps) {
            notes.add("checked over plain http: HSTS and cookie Secure flags are not expected");
        }

        int score = Math.max(0, 100 - penalty);
        return new Report(findings, score, grade(score), notes);
    }

    static String grade(int score) {
        if (score >= 90) {
            return "A";
        }
        if (score >= 80) {
            return "B";
        }
        if (score >= 70) {
            return "C";
        }
        if (score >= 60) {
            return "D";
        }
        return "F";
    }

    private static String first(Map<String, List<String>> headers, String name) {
        List<String> values = headers.get(name);
        if (values == null || values.isEmpty()) {
            return null;
        }
        return values.get(0);
    }

    // a CSP policy can be huge; keep the output line readable
    private static String shorten(String value) {
        return value.length() <= 70 ? value : value.substring(0, 67) + "...";
    }
}

package com.github.isaacadams135.headerchecker;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class HeaderEvaluatorTest {

    @Test
    void fullHeaderSetScoresGradeA() {
        Report report = HeaderEvaluator.evaluate(goodHeaders(), true);

        assertEquals(100, report.score());
        assertEquals("A", report.grade());
        assertEquals(6, report.findings().size());
        assertTrue(report.findings().stream().allMatch(f -> f.status() == Finding.Status.PASS));
    }

    @Test
    void emptyHeadersScoreLowOnHttps() {
        Report report = HeaderEvaluator.evaluate(Map.of(), true);

        assertEquals(28, report.score()); // six missing majors at 12 points each
        assertEquals("F", report.grade());
        assertEquals(6, count(report, Finding.Status.FAIL));
    }

    @Test
    void hstsMissingOnHttpsFailsButOnHttpIsInformational() {
        Map<String, List<String>> headers = goodHeaders();
        headers.remove("Strict-Transport-Security");

        Report overHttps = HeaderEvaluator.evaluate(headers, true);
        assertEquals(88, overHttps.score());
        assertEquals(Finding.Status.FAIL, find(overHttps, "Strict-Transport-Security").status());

        Report overHttp = HeaderEvaluator.evaluate(headers, false);
        assertEquals(100, overHttp.score());
        assertEquals(Finding.Status.INFO, find(overHttp, "Strict-Transport-Security").status());
    }

    @Test
    void cookieFlagsProduceFindingsAndPenalties() {
        Map<String, List<String>> headers = goodHeaders();
        headers.put("Set-Cookie", List.of("session=abc123", "id=7; HttpOnly; Secure; SameSite=Strict"));

        Report overHttps = HeaderEvaluator.evaluate(headers, true);
        assertEquals(95, overHttps.score());
        assertTrue(hasNote(overHttps, "cookie session", "missing HttpOnly"));
        assertTrue(hasNote(overHttps, "cookie session", "missing Secure"));
        assertTrue(hasNote(overHttps, "cookie session", "missing SameSite"));
        assertTrue(overHttps.findings().stream().noneMatch(f -> f.name().equals("cookie id")));

        Report overHttp = HeaderEvaluator.evaluate(headers, false);
        assertEquals(95, overHttp.score());
        assertTrue(overHttp.findings().stream().noneMatch(f -> f.note().equals("missing Secure")));
    }

    @Test
    void serverVersionDisclosureIsWarned() {
        Map<String, List<String>> headers = goodHeaders();
        headers.put("Server", List.of("nginx/1.25.3"));
        headers.put("X-Powered-By", List.of("PHP/8.2.1"));
        headers.put("X-AspNet-Version", List.of("4.0.30319"));

        Report report = HeaderEvaluator.evaluate(headers, true);
        assertEquals(85, report.score());
        assertEquals("B", report.grade());
        assertTrue(find(report, "Server").note().contains("version disclosed"));
        assertTrue(find(report, "X-Powered-By").note().contains("version disclosed"));
        assertTrue(find(report, "X-AspNet-Version").note().contains("version disclosed"));

        Map<String, List<String>> noVersion = goodHeaders();
        noVersion.put("Server", List.of("cloudflare"));
        Report plain = HeaderEvaluator.evaluate(noVersion, true);
        assertEquals(100, plain.score());
        assertEquals(Finding.Status.INFO, find(plain, "Server").status());
    }

    @Test
    void gradeBoundariesLandOnTheRightSide() {
        Map<String, List<String>> a = goodHeaders();
        a.put("Server", List.of("nginx/1.25.3"));
        a.put("X-Powered-By", List.of("PHP/8.1"));
        Report aReport = HeaderEvaluator.evaluate(a, true);
        assertEquals(90, aReport.score());
        assertEquals("A", aReport.grade());

        Map<String, List<String>> b = goodHeaders();
        b.put("Server", List.of("nginx/1.25.3"));
        b.put("X-Powered-By", List.of("PHP/8.1"));
        b.put("X-AspNet-Version", List.of("4.0.30319"));
        b.put("Set-Cookie", List.of("a=1"));
        Report bReport = HeaderEvaluator.evaluate(b, true);
        assertEquals(80, bReport.score());
        assertEquals("B", bReport.grade());

        Map<String, List<String>> c = goodHeaders();
        c.put("Set-Cookie", List.of("c1=1", "c2=2", "c3=3", "c4=4", "c5=5", "c6=6"));
        Report cReport = HeaderEvaluator.evaluate(c, true);
        assertEquals(70, cReport.score());
        assertEquals("C", cReport.grade());

        Map<String, List<String>> d = goodHeaders();
        d.put("Set-Cookie", List.of("d1=1", "d2=2", "d3=3", "d4=4", "d5=5", "d6=6", "d7=7", "d8=8"));
        Report dReport = HeaderEvaluator.evaluate(d, true);
        assertEquals(60, dReport.score());
        assertEquals("D", dReport.grade());

        Map<String, List<String>> f = goodHeaders();
        f.remove("X-Frame-Options");
        f.remove("Referrer-Policy");
        f.put("Set-Cookie", List.of("f1=1", "f2=2", "f3=3", "f4=4", "f5=5", "f6=6", "f7=7"));
        Report fReport = HeaderEvaluator.evaluate(f, true);
        assertEquals(41, fReport.score());
        assertEquals("F", fReport.grade());
    }

    @Test
    void nosniffWrongValueFails() {
        Map<String, List<String>> headers = goodHeaders();
        headers.put("X-Content-Type-Options", List.of("whatever"));

        Report report = HeaderEvaluator.evaluate(headers, true);

        assertEquals(88, report.score());
        Finding finding = find(report, "X-Content-Type-Options");
        assertEquals(Finding.Status.FAIL, finding.status());
        assertTrue(finding.note().contains("nosniff"));
    }

    private static Map<String, List<String>> goodHeaders() {
        Map<String, List<String>> headers = new LinkedHashMap<>();
        headers.put("Strict-Transport-Security", List.of("max-age=63072000; includeSubDomains"));
        headers.put("Content-Security-Policy", List.of("default-src 'self'"));
        headers.put("X-Content-Type-Options", List.of("nosniff"));
        headers.put("X-Frame-Options", List.of("SAMEORIGIN"));
        headers.put("Referrer-Policy", List.of("no-referrer"));
        headers.put("Permissions-Policy", List.of("camera=()"));
        return headers;
    }

    private static boolean hasNote(Report report, String name, String note) {
        return report.findings().stream()
                .anyMatch(f -> f.name().equals(name) && f.note().equals(note));
    }

    private static Finding find(Report report, String name) {
        return report.findings().stream()
                .filter(f -> f.name().equals(name))
                .findFirst()
                .orElseThrow(() -> new AssertionError("no finding for " + name));
    }

    private static long count(Report report, Finding.Status status) {
        return report.findings().stream().filter(f -> f.status() == status).count();
    }
}

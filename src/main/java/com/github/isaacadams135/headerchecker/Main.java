package com.github.isaacadams135.headerchecker;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.regex.Pattern;

public final class Main {

    private static final String USAGE = """
        usage: header-checker [options] <url>

        checks a site's HTTP security headers, cookies and TLS setup,
        then prints a letter grade (A-F) like securityheaders.com

        options:
          -t, --timeout <seconds>   request timeout in seconds (default: 10)
          -h, --help                show this help
        """;

    // a real scheme has "://" after it, so "localhost:8080" still gets https:// prepended
    private static final Pattern HAS_SCHEME = Pattern.compile("^[a-zA-Z][a-zA-Z0-9+.\\-]*://.*");

    private Main() {
    }

    public static void main(String[] args) {
        Options opts;
        try {
            opts = Options.parse(args);
        } catch (IllegalArgumentException e) {
            System.err.println("error: " + e.getMessage());
            System.err.println(USAGE);
            System.exit(2);
            return;
        }

        if (opts.help()) {
            System.out.println(USAGE);
            return;
        }

        URI target = opts.uri();
        HttpClient client = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NORMAL)
                .connectTimeout(Duration.ofSeconds(opts.timeout()))
                .build();
        HttpRequest request = HttpRequest.newBuilder(target)
                .timeout(Duration.ofSeconds(opts.timeout()))
                .GET()
                .build();

        HttpResponse<Void> response;
        try {
            response = client.send(request, HttpResponse.BodyHandlers.discarding());
        } catch (IOException e) {
            System.err.println("error: request to " + target + " failed: " + e.getMessage());
            System.exit(1);
            return;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            System.err.println("error: interrupted");
            System.exit(1);
            return;
        }

        URI finalUri = response.uri();
        boolean isHttps = "https".equalsIgnoreCase(finalUri.getScheme());

        System.out.printf("%-6s %s%n", "url", finalUri);
        if (!finalUri.equals(target)) {
            boolean upgraded = "http".equalsIgnoreCase(target.getScheme()) && isHttps;
            System.out.printf("%-6s %s%s%n", "from", target, upgraded ? " (http upgraded to https)" : "");
        }
        System.out.printf("%-6s %d%n", "code", response.statusCode());
        System.out.println();

        Report report = HeaderEvaluator.evaluate(response.headers().map(), isHttps);
        System.out.printf("%-6s %-26s %s%n", "status", "header", "note");
        for (Finding finding : report.findings()) {
            System.out.printf("%-6s %-26s %s%n", finding.status(), finding.name(), finding.note());
        }

        if (!report.notes().isEmpty()) {
            System.out.println();
            for (String note : report.notes()) {
                System.out.printf("%-6s %s%n", "note", note);
            }
        }

        System.out.println();
        System.out.printf("%-6s %d/100  grade %s%n", "score", report.score(), report.grade());

        if (isHttps) {
            String host = finalUri.getHost();
            int port = finalUri.getPort() > 0 ? finalUri.getPort() : 443;
            System.out.println();
            TlsInspector.inspect(host, port, opts.timeout() * 1000);
        }
    }

    record Options(URI uri, int timeout, boolean help) {

        static Options parse(String[] args) {
            URI uri = null;
            int timeout = 10;
            boolean help = false;

            for (int i = 0; i < args.length; i++) {
                String arg = args[i];
                switch (arg) {
                    case "-h", "--help" -> help = true;
                    case "-t", "--timeout" -> timeout = Integer.parseInt(nextValue(args, ++i, arg));
                    default -> {
                        if (arg.startsWith("-")) {
                            throw new IllegalArgumentException("unknown option: " + arg);
                        }
                        if (uri != null) {
                            throw new IllegalArgumentException("unexpected argument: " + arg);
                        }
                        uri = toUri(arg);
                    }
                }
            }

            if (help) {
                return new Options(null, 0, true);
            }
            if (uri == null) {
                throw new IllegalArgumentException("missing url");
            }
            if (timeout < 1) {
                throw new IllegalArgumentException("timeout must be at least 1 second");
            }
            return new Options(uri, timeout, false);
        }

        private static URI toUri(String arg) {
            String url = HAS_SCHEME.matcher(arg).find() ? arg : "https://" + arg;
            URI uri;
            try {
                uri = URI.create(url);
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException("bad url: " + arg);
            }
            if (uri.getHost() == null) {
                throw new IllegalArgumentException("bad url (no host): " + arg);
            }
            String scheme = uri.getScheme();
            if (!"http".equalsIgnoreCase(scheme) && !"https".equalsIgnoreCase(scheme)) {
                throw new IllegalArgumentException("unsupported scheme: " + scheme);
            }
            return uri;
        }

        private static String nextValue(String[] args, int index, String option) {
            if (index >= args.length) {
                throw new IllegalArgumentException(option + " needs a value");
            }
            return args[index];
        }
    }
}

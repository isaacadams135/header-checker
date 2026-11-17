# header-checker

Checks a website's HTTP security headers, cookies and TLS setup, then prints a letter grade (A-F) like securityheaders.com. I built it because I kept pasting my own sites into web formatters just to see whether I forgot a header, and I wanted the same check as a CLI I can script. Works as a normal user on JDK 21+ with no dependencies beyond the JDK.

## Features

- Grades the six major headers (HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy) with a fixed, readable penalty table
- Checks cookies for HttpOnly, Secure and SameSite flags
- Flags server software disclosure (Server, X-Powered-By, X-AspNet-Version) and warns when a version number leaks
- Reports the final URL after redirects and notes when http was upgraded to https
- Shows the negotiated TLS protocol, cipher suite and certificate expiry with days remaining
- Scoring and grading live in one pure function, so the whole thing is unit tested without any network

## Build

Requires JDK 21+.

```bash
./gradlew build
./gradlew jar
```

On Windows use `gradlew.bat`.

## Usage

```bash
./gradlew run --args="https://example.com"
./gradlew run --args="example.com -t 5"
./gradlew run --args="--help"
```

A bare host gets `https://` prepended. Exit codes: 0 after a completed check (even a failing grade), 1 on network/parse failure, 2 on usage error.

Real output from `header-checker https://example.com`:

```text
url    https://example.com
code   200

status header                     note
FAIL   Strict-Transport-Security  missing
FAIL   Content-Security-Policy    missing
FAIL   X-Content-Type-Options     missing
FAIL   X-Frame-Options            missing
FAIL   Referrer-Policy            missing
FAIL   Permissions-Policy         missing
INFO   Server                     cloudflare

score  28/100  grade F

tls    protocol                   TLSv1.3
tls    cipher                     TLS_AES_256_GCM_SHA384
tls    expires                    2026-12-25 (73 days)
```

## How it works

The tool makes one GET request with `java.net.http.HttpClient` (redirects followed, body discarded — only the headers matter) and evaluates the final response's headers case-insensitively. Scoring starts at 100 and subtracts the penalty table: 12 per missing major header, 5 per disclosed version, 5 per insecure cookie, clamped at 0, then mapped to a letter grade. When the final URL is https it also opens a separate `SSLSocket` to report the negotiated TLS details.

## Only use it on stuff you're allowed to

Authorized targets only.

## License

MIT

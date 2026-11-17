package com.github.isaacadams135.headerchecker;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/**
 * One-shot TLS probe: handshakes with host:port and reports the negotiated
 * protocol, cipher and certificate expiry. Network only, never unit tested.
 */
public final class TlsInspector {

    private TlsInspector() {
    }

    public static void inspect(String host, int port, int timeoutMillis) {
        try (SSLSocket socket = (SSLSocket) SSLSocketFactory.getDefault().createSocket()) {
            socket.connect(new InetSocketAddress(host, port), timeoutMillis);
            SSLParameters params = socket.getSSLParameters();
            try {
                params.setServerNames(List.of(new SNIHostName(host)));
            } catch (IllegalArgumentException e) {
                // IP literal - there is no hostname to send in SNI
            }
            socket.setSSLParameters(params);
            socket.setSoTimeout(timeoutMillis);
            socket.startHandshake();

            SSLSession session = socket.getSession();
            System.out.printf("%-6s %-26s %s%n", "tls", "protocol", session.getProtocol());
            System.out.printf("%-6s %-26s %s%n", "tls", "cipher", session.getCipherSuite());

            Certificate[] chain = session.getPeerCertificates();
            if (chain.length > 0 && chain[0] instanceof X509Certificate cert) {
                String expiry = cert.getNotAfter().toInstant()
                        .atZone(ZoneId.systemDefault())
                        .toLocalDate()
                        .format(DateTimeFormatter.ISO_LOCAL_DATE);
                long days = TimeUnit.MILLISECONDS.toDays(cert.getNotAfter().getTime() - System.currentTimeMillis());
                System.out.printf("%-6s %-26s %s (%d days)%n", "tls", "expires", expiry, days);
            }
        } catch (IOException e) {
            // a dead or weird TLS endpoint is a result, not a crash
            System.out.printf("%-6s %-26s %s%n", "tls", "warning", e.getMessage());
        }
    }
}

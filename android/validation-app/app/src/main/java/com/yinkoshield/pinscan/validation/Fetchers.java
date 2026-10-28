package com.yinkoshield.pinscan.validation;

import java.security.GeneralSecurityException;
import java.util.List;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import okhttp3.CertificatePinner;
import okhttp3.ConnectionPool;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

/**
 * The HTTPS clients behind each posture, all built on OkHttp 4 so every attempt
 * is a fresh connection through the device's global HTTP proxy (how pinscan's
 * Android driver routes traffic). The platform {@code HttpsURLConnection} was
 * tried first and, after a certificate failure, let only the first attempt of a
 * launch reach the proxy; see docs/validation.md.
 *
 * Trust is still decided by the platform: with no socket factory set, OkHttp
 * uses Android's default {@code X509TrustManager}, which applies the app's
 * Network Security Config, pins included.
 */
final class Fetchers {
    /** Performs one GET and describes the outcome, or throws. */
    interface Fetcher {
        String fetch(String url) throws Exception;
    }

    private Fetchers() {
    }

    /** Platform trust only: the Network Security Config decides what is trusted and pinned. */
    static Fetcher plain() {
        return get(base().build());
    }

    /** OkHttp's CertificatePinner: the pin check runs after the handshake, so a mismatch closes the connection without a request. */
    static Fetcher okHttp(String host, List<String> pins) {
        CertificatePinner.Builder pinner = new CertificatePinner.Builder();
        for (String pin : pins) {
            pinner.add(host, "sha256/" + pin);
        }
        return get(base().certificatePinner(pinner.build()).build());
    }

    /** A custom X509TrustManager that pins inside the handshake, so a mismatch is a certificate alert on the wire. */
    static Fetcher trustManager(List<String> pins) throws GeneralSecurityException {
        X509TrustManager tm = new PinningTrustManager(pins);
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, new TrustManager[] {tm}, null);
        return get(base().sslSocketFactory(context.getSocketFactory(), tm).build());
    }

    private static OkHttpClient.Builder base() {
        return new OkHttpClient.Builder()
                .connectionPool(new ConnectionPool(0, 1, TimeUnit.SECONDS)) // no reuse between attempts
                .retryOnConnectionFailure(false)                            // one attempt is one connection
                .connectTimeout(10, TimeUnit.SECONDS)
                .readTimeout(10, TimeUnit.SECONDS);
    }

    private static Fetcher get(OkHttpClient client) {
        return url -> {
            Request request = new Request.Builder().url(url).header("Connection", "close").build();
            try (Response response = client.newCall(request).execute()) {
                return "HTTP " + response.code();
            }
        };
    }
}

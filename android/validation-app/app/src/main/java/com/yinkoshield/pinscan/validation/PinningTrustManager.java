package com.yinkoshield.pinscan.validation;

import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

/**
 * The "custom TrustManager" posture: the platform trust manager validates the
 * chain (so the research CA in the system store is honoured), then at least one
 * certificate in the chain must carry a pinned public key. The check runs inside
 * the handshake, so a failure is a certificate-class TLS alert on the wire.
 */
final class PinningTrustManager implements X509TrustManager {
    private final X509TrustManager platform;
    private final Set<String> pins;

    PinningTrustManager(Collection<String> pins) throws GeneralSecurityException {
        TrustManagerFactory factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        factory.init((KeyStore) null);
        X509TrustManager found = null;
        for (TrustManager tm : factory.getTrustManagers()) {
            if (tm instanceof X509TrustManager) {
                found = (X509TrustManager) tm;
                break;
            }
        }
        if (found == null) {
            throw new GeneralSecurityException("no platform X509TrustManager");
        }
        platform = found;
        this.pins = new HashSet<>(pins);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        platform.checkServerTrusted(chain, authType);
        for (X509Certificate cert : chain) {
            if (pins.contains(Pins.spkiSha256(cert))) {
                return;
            }
        }
        throw new CertificateException("pinscan validation: no pinned public key in the presented chain");
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        platform.checkClientTrusted(chain, authType);
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return platform.getAcceptedIssuers();
    }
}

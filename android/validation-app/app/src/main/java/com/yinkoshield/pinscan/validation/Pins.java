package com.yinkoshield.pinscan.validation;

import android.content.Context;
import android.content.res.XmlResourceParser;
import android.util.Base64;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;

/** The validation host and its SPKI pins, read from res/xml/nsc_pinned.xml so every posture uses the same values. */
final class Pins {
    /** The hostname the postures connect to. */
    final String host;
    /** Base64 SHA-256 of each pinned SubjectPublicKeyInfo. */
    final List<String> sha256;

    private Pins(String host, List<String> sha256) {
        this.host = host;
        this.sha256 = Collections.unmodifiableList(sha256);
    }

    /** Parses the pinned Network Security Config: the first domain and every pin under it. */
    static Pins load(Context context) {
        XmlResourceParser parser = context.getResources().getXml(R.xml.nsc_pinned);
        try {
            String host = null;
            List<String> pins = new ArrayList<>();
            for (int event = parser.getEventType(); event != XmlPullParser.END_DOCUMENT; event = parser.next()) {
                if (event != XmlPullParser.START_TAG) {
                    continue;
                }
                if ("domain".equals(parser.getName()) && host == null) {
                    host = parser.nextText().trim();
                } else if ("pin".equals(parser.getName())) {
                    pins.add(parser.nextText().trim());
                }
            }
            if (host == null || pins.isEmpty()) {
                throw new IllegalStateException("nsc_pinned.xml has no domain or no pin");
            }
            return new Pins(host, pins);
        } catch (XmlPullParserException | IOException e) {
            throw new IllegalStateException("nsc_pinned.xml: " + e, e);
        } finally {
            parser.close();
        }
    }

    /** The pin of a certificate: base64(SHA-256(DER SubjectPublicKeyInfo)), as NSC and OkHttp define it. */
    static String spkiSha256(X509Certificate cert) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(cert.getPublicKey().getEncoded());
            return Base64.encodeToString(digest, Base64.NO_WRAP);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}

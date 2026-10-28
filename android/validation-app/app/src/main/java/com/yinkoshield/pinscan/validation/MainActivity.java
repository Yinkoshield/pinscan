package com.yinkoshield.pinscan.validation;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.util.Log;
import android.webkit.SslErrorHandler;
import android.webkit.WebResourceError;
import android.webkit.WebResourceRequest;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.net.http.SslError;

import java.security.GeneralSecurityException;

/**
 * Launcher activity. The posture is fixed at build time ({@link BuildConfig#POSTURE},
 * one product flavor each); on launch it makes a few HTTPS requests to the
 * validation host with that posture's client and shows the outcome. pinscan
 * launches it with the LAUNCHER intent for every wave, so no extras are needed.
 */
public final class MainActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Pins pins = Pins.load(this);
        String posture = BuildConfig.POSTURE;

        TextView out = new TextView(this);
        out.setPadding(32, 32, 32, 32);
        out.setText("pinscan validation\nposture: " + posture + "\nhost: " + pins.host
                + "\npins: " + pins.sha256.size() + "\n\n");
        Runner.Sink sink = line -> runOnUiThread(() -> out.append(line + "\n"));
        Log.i(Runner.TAG, "launch posture=" + posture + " host=" + pins.host + " pins=" + pins.sha256.size());

        if ("webview".equals(posture)) {
            showWebView(out, pins.host);
            return;
        }
        ScrollView scroll = new ScrollView(this);
        scroll.addView(out);
        setContentView(scroll);

        try {
            switch (posture) {
                case "netproc":
                    startService(new Intent(this, NetService.class));
                    sink.line("requests delegated to the :net process; see logcat tag " + Runner.TAG);
                    break;
                case "okhttp":
                    Runner.run(posture, pins.host, Fetchers.okHttp(pins.host, pins.sha256), sink);
                    break;
                case "trustmanager":
                    Runner.run(posture, pins.host, Fetchers.trustManager(pins.sha256), sink);
                    break;
                default: // nopin, nscok, nscwrong: the Network Security Config decides.
                    Runner.run(posture, pins.host, Fetchers.plain(), sink);
                    break;
            }
        } catch (GeneralSecurityException e) {
            sink.line("setup failed: " + e);
            Log.e(Runner.TAG, "setup failed", e);
        }
    }

    /** The WebView posture: Chromium's stack, loading the host a few times; it pins nothing itself. */
    private void showWebView(TextView out, String host) {
        WebView web = new WebView(this);
        web.setWebViewClient(new WebViewClient() {
            private int attempt = 1;
            private boolean pending = true; // one report per load: an error and onPageFinished can both fire

            @Override
            public void onPageFinished(WebView view, String url) {
                report("ok loaded " + url);
            }

            @Override
            public void onReceivedError(WebView view, WebResourceRequest request, WebResourceError error) {
                if (request.isForMainFrame()) {
                    report("fail " + error.getDescription() + " " + request.getUrl());
                }
            }

            @Override
            public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {
                report("ssl error (cancelled) " + error);
                handler.cancel(); // never proceed past a certificate error
            }

            private void report(String outcome) {
                if (!pending) {
                    return;
                }
                pending = false;
                String line = "webview attempt " + attempt + "/" + Runner.ATTEMPTS + " " + host + ": " + outcome;
                Log.i(Runner.TAG, line);
                out.append(line + "\n");
                if (attempt < Runner.ATTEMPTS) {
                    attempt++;
                    web.postDelayed(() -> {
                        pending = true;
                        web.loadUrl(url(attempt));
                    }, 1_500);
                }
            }

            private String url(int n) {
                return "https://" + host + "/?pinscan=webview&attempt=" + n;
            }
        });
        LinearLayout column = new LinearLayout(this);
        column.setOrientation(LinearLayout.VERTICAL);
        column.addView(out, new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT));
        column.addView(web, new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f));
        setContentView(column);
        web.loadUrl("https://" + host + "/?pinscan=webview&attempt=1");
    }
}

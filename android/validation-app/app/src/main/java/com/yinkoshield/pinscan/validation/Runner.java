package com.yinkoshield.pinscan.validation;

import android.util.Log;

/** Runs a posture's fetcher a few times on a background thread, logging each attempt. */
final class Runner {
    /** The logcat tag scripts/validate-device.sh collects as evidence. */
    static final String TAG = "PINSCAN_VALIDATION";
    /** Attempts per launch: two or more consistent attempts give pinscan a high-confidence verdict. */
    static final int ATTEMPTS = 3;
    private static final long PAUSE_MS = 1_500;

    /** Receives one line per attempt, off the main thread. */
    interface Sink {
        void line(String text);
    }

    private Runner() {
    }

    static void run(String posture, String host, Fetchers.Fetcher fetcher, Sink sink) {
        Thread thread = new Thread(() -> {
            for (int attempt = 1; attempt <= ATTEMPTS; attempt++) {
                String url = "https://" + host + "/?pinscan=" + posture + "&attempt=" + attempt;
                String outcome;
                try {
                    outcome = "ok " + fetcher.fetch(url);
                } catch (Exception e) {
                    outcome = "fail " + e.getClass().getSimpleName() + ": " + e.getMessage();
                }
                String line = posture + " attempt " + attempt + "/" + ATTEMPTS + " " + host + ": " + outcome;
                Log.i(TAG, line);
                sink.line(line);
                try {
                    Thread.sleep(PAUSE_MS);
                } catch (InterruptedException e) {
                    return;
                }
            }
        }, "pinscan-validation");
        thread.setDaemon(true);
        thread.start();
    }
}

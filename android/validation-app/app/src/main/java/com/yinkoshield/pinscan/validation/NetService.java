package com.yinkoshield.pinscan.validation;

import android.app.Service;
import android.content.Intent;
import android.os.IBinder;
import android.os.Process;
import android.util.Log;

/**
 * The netproc posture's TLS client. The manifest runs this service in a second
 * process, {@code <package>:net}, while the activity stays in the main process.
 * The client itself does no pinning; what the posture tests is whether the
 * scoped-mode CA bind reaches a process whose name is not the package name.
 */
public final class NetService extends Service {
    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        Log.i(Runner.TAG, "netproc: fetching from process " + Process.myPid() + " (" + currentProcessName() + ")");
        Runner.run("netproc", Pins.load(this).host, Fetchers.plain(), line -> { });
        return START_NOT_STICKY;
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    private static String currentProcessName() {
        try {
            return android.app.Application.getProcessName();
        } catch (Throwable t) {
            return "?"; // API < 28
        }
    }
}

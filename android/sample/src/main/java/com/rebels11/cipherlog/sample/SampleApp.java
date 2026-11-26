package com.rebels11.cipherlog.sample;

import android.app.Application;
import com.rebels11.cipherlog.android.CipherLog;
import com.rebels11.cipherlog.android.OptionalCollectors;

/** The whole integration: one start per process, then CipherLog.d/i/w/e wherever android.util.Log was. */
public final class SampleApp extends Application {
    /**
     * The TEST public key from vectors/test-key.json. Anyone with the published test private key can read these logs.
     * A real app ships its own key and has a test that fails if it equals this one.
     */
    static final String TEST_KEY =
            "cipherlog-pub-v1:ecd8b29e913351f6a28fda6e663ad350273ed38a9b44fe8f1b8116a236154170";

    @Override
    public void onCreate() {
        super.onCreate();
        // The optional device collectors (version history, install dates, memory, screen, network, storage) are off by
        // default; the sample opts into all six so they show up in its device block.
        CipherLog.start(this, TEST_KEY, new CipherLog.Options().addCollectors(OptionalCollectors.all(this)));
        CipherLog.i("App", "started");

        // cipherlog installs no crash handler; an app's own handler can flush the file before the process dies.
        final Thread.UncaughtExceptionHandler previous = Thread.getDefaultUncaughtExceptionHandler();
        Thread.setDefaultUncaughtExceptionHandler((thread, error) -> {
            try {
                CipherLog.wtf("Crash", "uncaught on " + thread.getName(), error);
                CipherLog.flush(500);
            } finally {
                if (previous != null) previous.uncaughtException(thread, error);
            }
        });
    }
}

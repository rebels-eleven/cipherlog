package com.rebels11.cipherlog;

import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** Runs inside the Tink-less class loader of {@link NoTinkTest}; uses only the public API. */
public final class NoTinkProbe {
    private NoTinkProbe() {
    }

    /** Diagnostics lines, then isOn, then how many files are left. */
    public static List<String> run(File dir) {
        final List<String> diagnostics = Collections.synchronizedList(new ArrayList<String>());
        CipherLogKey key = CipherLogKey.parse(
                "cipherlog-pub-v1:ecd8b29e913351f6a28fda6e663ad350273ed38a9b44fe8f1b8116a236154170") /* the test key */;
        CipherLog log = new CipherLog(CipherLogConfig.builder(dir, key)
                .diagnostics(new CipherLogConfig.Diagnostics() {
                    @Override
                    public void report(String line) {
                        diagnostics.add(line);
                    }
                }).build());
        log.log(CipherLogLevel.W, "a", "never written");
        log.flush(2000);
        log.recentBundle(2000);
        List<String> out = new ArrayList<>(diagnostics);
        out.add(String.valueOf(log.isOn()));
        File[] files = dir.listFiles();
        out.add(String.valueOf(files == null ? 0 : files.length));
        log.close();
        return out;
    }
}

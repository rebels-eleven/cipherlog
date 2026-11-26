package com.rebels11.cipherlog.android;

import android.app.ActivityManager;
import android.app.Application;
import android.content.Context;
import android.os.Build;
import android.os.Process;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.util.List;

/** The process name and number of SPEC.md 7.1 on Android. */
final class ProcessNames {
    private ProcessNames() {
    }

    /** The number and file name of a process: the main process is 1 {@code app}, any other 2 and its own name. */
    static final class Detected {
        final int process;
        final String name;

        Detected(int process, String name) {
            this.process = process;
            this.name = name;
        }
    }

    /** {@code com.example} → 1 {@code app}; {@code com.example:sync} → 2 {@code sync}; {@code other.proc} → 2 as is. */
    static Detected of(String processName, String packageName) {
        if (processName == null || processName.isEmpty() || processName.equals(packageName)) {
            return new Detected(1, "app");
        }
        if (packageName != null && processName.startsWith(packageName + ":")) {
            String suffix = processName.substring(packageName.length() + 1);
            return new Detected(2, suffix.isEmpty() ? "app" : suffix);
        }
        int colon = processName.lastIndexOf(':');
        return new Detected(2, colon >= 0 && colon + 1 < processName.length() ? processName.substring(colon + 1) : processName);
    }

    /** Tests on a plain JVM set this: there /proc/self/cmdline names the JVM, not an app process. */
    static volatile String forcedForTests;

    /** The running process's name: Application.getProcessName on 28+, then /proc/self/cmdline, then ActivityManager. */
    static String current(Context context) {
        String forced = forcedForTests;
        if (forced != null) return forced;
        if (Build.VERSION.SDK_INT >= 28) {
            try {
                String name = Application.getProcessName();
                if (name != null && !name.isEmpty()) return name;
            } catch (Throwable ignored) {
                // Fall through.
            }
        }
        try {
            String name = fromCmdline(readCmdline());
            if (name != null) return name;
        } catch (Throwable ignored) {
            // Fall through.
        }
        try {
            ActivityManager am = (ActivityManager) context.getSystemService(Context.ACTIVITY_SERVICE);
            List<ActivityManager.RunningAppProcessInfo> running = am == null ? null : am.getRunningAppProcesses();
            if (running != null) {
                int pid = Process.myPid();
                for (ActivityManager.RunningAppProcessInfo info : running) {
                    if (info.pid == pid && info.processName != null) return info.processName;
                }
            }
        } catch (Throwable ignored) {
            // Fall through.
        }
        return context.getPackageName();
    }

    private static byte[] readCmdline() throws IOException {
        try (InputStream in = new FileInputStream("/proc/self/cmdline")) {
            byte[] buffer = new byte[512];
            int length = 0;
            int n;
            while (length < buffer.length && (n = in.read(buffer, length, buffer.length - length)) > 0) length += n;
            byte[] out = new byte[length];
            System.arraycopy(buffer, 0, out, 0, length);
            return out;
        }
    }

    /** The first NUL-terminated field of /proc/self/cmdline, or null when it is empty. */
    static String fromCmdline(byte[] cmdline) {
        int end = 0;
        while (end < cmdline.length && cmdline[end] != 0) end++;
        String name = new String(cmdline, 0, end, Charset.forName("UTF-8")).trim();
        return name.isEmpty() ? null : name;
    }
}

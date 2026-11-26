package com.rebels11.cipherlog.android;

import android.Manifest;
import android.annotation.SuppressLint;
import android.app.ActivityManager;
import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.res.Configuration;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.os.Build;
import android.os.PowerManager;
import com.rebels11.cipherlog.CipherLogCollector;
import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/**
 * Device-block collectors an app may add; none of them is in {@link DeviceCollectors#defaults}. One line opts into all:
 *
 * <pre>{@code
 * CipherLog.start(this, KEY, new CipherLog.Options().addCollectors(OptionalCollectors.all(this)));
 * }</pre>
 *
 * <ul>
 *   <li>{@code versionHistory · 1.4.1 (16) since 2026-11-20 · 1.4 (15) since 2026-11-12} — every version first seen on
 *       this device, newest first, at most 20, kept in the private SharedPreferences file {@code cipherlog}. The running
 *       version is recorded when the collector is created and again whenever a file opens.</li>
 *   <li>{@code installDates · installed 2026-11-01 · updated 2026-11-20} — {@code PackageInfo.firstInstallTime} and
 *       {@code lastUpdateTime}, UTC days.</li>
 *   <li>{@code memory · RAM 7.5 GB · class 256 MB · large class 512 MB · low-RAM device no · low memory now no · power
 *       save off} — total RAM rounded to 0.5 GB (binary GB).</li>
 *   <li>{@code screen · 411×914 dp · xxhdpi (420 dpi) · font 1.15 · dark yes}.</li>
 *   <li>{@code network · wifi · expensive no · constrained no} — the connection type only ({@code wifi},
 *       {@code cellular}, {@code ethernet}, {@code none}, {@code other}); expensive = metered, constrained = metered
 *       and Data Saver restricts this app (Data Saver leaves unmetered networks alone). Needs {@code ACCESS_NETWORK_STATE}, which cipherlog does not add to the manifest; without
 *       it the line is {@code unknown (no ACCESS_NETWORK_STATE)}.</li>
 *   <li>{@code storageUsage · files 1.2 MB · cache 340 KB · no_backup 12.0 MB · databases 3.1 MB · logs 2.0 MB} —
 *       sizes of the app's own folders ({@code logs} is the cipherlog directory, also counted in its parent; with
 *       {@code Options.directory(...)} pass that directory to {@link #all(Context, File)}). Logical file lengths. The
 *       walk stops after 50 000 entries or 200 ms in all; a folder it did not finish reads
 *       {@code ≥ <what was counted>}, a folder it never reached {@code not counted}, a missing one {@code none}.</li>
 * </ul>
 *
 * <p>None of them collects names, accounts, ids, network names or addresses, carrier names or file names. Creating a
 * collector never throws; a collector that fails while a file opens gives {@code <name> · failed <type>}.
 */
public final class OptionalCollectors {
    private OptionalCollectors() {
    }

    /** All six, in the order above, for {@code Options.addCollectors}; {@code logs} is the default log directory. */
    public static List<CipherLogCollector> all(Context context) {
        return all(context, null);
    }

    /**
     * As {@link #all(Context)}, for an app that moved its logs with {@code Options.directory(...)}: pass the same
     * directory, so {@code storageUsage} measures it as {@code logs} (null = the default directory).
     */
    public static List<CipherLogCollector> all(Context context, File logDirectory) {
        List<CipherLogCollector> out = new ArrayList<>();
        out.add(versionHistory(context));
        out.add(installDates(context));
        out.add(memory(context));
        out.add(screen(context));
        out.add(network(context));
        out.add(storageUsage(context, logDirectory));
        return Collections.unmodifiableList(out);
    }

    private static Context app(Context context) {
        Context app = context.getApplicationContext();
        return app != null ? app : context;
    }

    // ---- versionHistory ----

    /** Every app version first seen on this device, with the UTC day it was first seen. */
    public static CipherLogCollector versionHistory(Context context) {
        final Context app = app(context);
        final VersionHistory.Store store = new PreferencesStore(app);
        try {
            recordRunningVersion(app, store);
        } catch (Throwable ignored) {
            // Recorded again when a file opens; a failure there becomes "failed <type>".
        }
        return CipherLogCollector.of("versionHistory",
                () -> Collections.singletonList(VersionHistory.format(recordRunningVersion(app, store))));
    }

    private static List<VersionHistory.Entry> recordRunningVersion(Context app, VersionHistory.Store store)
            throws PackageManager.NameNotFoundException {
        PackageInfo info = app.getPackageManager().getPackageInfo(app.getPackageName(), 0);
        return VersionHistory.record(store, info.versionName, versionCode(info), System.currentTimeMillis());
    }

    private static long versionCode(PackageInfo info) {
        return Build.VERSION.SDK_INT >= 28 ? info.getLongVersionCode() : legacyVersionCode(info);
    }

    @SuppressWarnings("deprecation")
    private static long legacyVersionCode(PackageInfo info) {
        return info.versionCode;
    }

    /** SharedPreferences file {@code cipherlog}, private to the app. */
    static final class PreferencesStore implements VersionHistory.Store {
        private final Context context;

        PreferencesStore(Context context) {
            this.context = context;
        }

        private SharedPreferences prefs() {
            SharedPreferences prefs = context.getSharedPreferences("cipherlog", Context.MODE_PRIVATE);
            if (prefs == null) throw new IllegalStateException("no SharedPreferences");
            return prefs;
        }

        @Override
        public String get(String key) {
            return prefs().getString(key, null);
        }

        @Override
        public void put(String key, String value) {
            prefs().edit().putString(key, value).apply();
        }
    }

    // ---- installDates ----

    /** {@code installed 2026-11-01 · updated 2026-11-20} (UTC days). */
    public static CipherLogCollector installDates(Context context) {
        final Context app = app(context);
        return CipherLogCollector.of("installDates", () -> {
            PackageInfo info = app.getPackageManager().getPackageInfo(app.getPackageName(), 0);
            return Collections.singletonList(installLine(info.firstInstallTime, info.lastUpdateTime));
        });
    }

    static String installLine(long firstInstall, long lastUpdate) {
        return "installed " + day(firstInstall) + " · updated " + day(lastUpdate);
    }

    private static String day(long millis) {
        return millis > 0 ? VersionHistory.utcDay(millis) : "unknown";
    }

    // ---- memory ----

    /** Total RAM, the app's heap classes, low-RAM device, low memory now, power save. */
    public static CipherLogCollector memory(Context context) {
        final Context app = app(context);
        return CipherLogCollector.of("memory", () -> {
            ActivityManager am = (ActivityManager) app.getSystemService(Context.ACTIVITY_SERVICE);
            if (am == null) return Collections.singletonList("unknown");
            ActivityManager.MemoryInfo info = new ActivityManager.MemoryInfo();
            am.getMemoryInfo(info);
            PowerManager pm = (PowerManager) app.getSystemService(Context.POWER_SERVICE);
            Boolean powerSave = pm == null ? null : pm.isPowerSaveMode();
            return Collections.singletonList(memoryLine(info.totalMem, am.getMemoryClass(), am.getLargeMemoryClass(),
                    am.isLowRamDevice(), info.lowMemory, powerSave));
        });
    }

    static String memoryLine(long totalBytes, int memoryClassMb, int largeMemoryClassMb, boolean lowRamDevice,
            boolean lowMemoryNow, Boolean powerSave) {
        return "RAM " + halfGb(totalBytes) + " · class " + memoryClassMb + " MB · large class " + largeMemoryClassMb
                + " MB · low-RAM device " + yesNo(lowRamDevice) + " · low memory now " + yesNo(lowMemoryNow)
                + " · power save " + (powerSave == null ? "unknown" : powerSave ? "on" : "off");
    }

    /** Rounded to the nearest 0.5 GB (2^30 bytes): {@code 7.5 GB}, {@code 8 GB}; {@code unknown} for 0. */
    static String halfGb(long bytes) {
        if (bytes <= 0) return "unknown";
        long halves = Math.round(bytes / (double) (1L << 30) * 2);
        if (halves % 2 == 0) return (halves / 2) + " GB";
        return (halves / 2) + ".5 GB";
    }

    private static String yesNo(boolean value) {
        return value ? "yes" : "no";
    }

    // ---- screen ----

    /** Size in dp, density bucket and dpi, font scale, dark theme. Safe on any thread. */
    public static CipherLogCollector screen(Context context) {
        final Context app = app(context);
        return CipherLogCollector.of("screen", () -> {
            Configuration c = app.getResources().getConfiguration();
            boolean dark = (c.uiMode & Configuration.UI_MODE_NIGHT_MASK) == Configuration.UI_MODE_NIGHT_YES;
            return Collections.singletonList(
                    screenLine(c.screenWidthDp, c.screenHeightDp, c.densityDpi, c.fontScale, dark));
        });
    }

    static String screenLine(int widthDp, int heightDp, int densityDpi, float fontScale, boolean dark) {
        return widthDp + "×" + heightDp + " dp · " + densityBucket(densityDpi) + " (" + densityDpi + " dpi) · font "
                + fontScale(fontScale) + " · dark " + yesNo(dark);
    }

    /** The resource bucket a density falls in: the smallest one at or above it. */
    static String densityBucket(int dpi) {
        if (dpi <= 0) return "unknown";
        if (dpi <= 120) return "ldpi";
        if (dpi <= 160) return "mdpi";
        if (dpi <= 213) return "tvdpi";
        if (dpi <= 240) return "hdpi";
        if (dpi <= 320) return "xhdpi";
        if (dpi <= 480) return "xxhdpi";
        return "xxxhdpi";
    }

    /** {@code 1}, {@code 1.15}, {@code 0.85}: two decimals at most, no trailing zeros. */
    static String fontScale(float scale) {
        String s = String.format(Locale.ROOT, "%.2f", scale);
        while (s.endsWith("0")) s = s.substring(0, s.length() - 1);
        if (s.endsWith(".")) s = s.substring(0, s.length() - 1);
        return s;
    }

    // ---- network ----

    /** Connection type and the expensive / constrained flags; never names or addresses. */
    public static CipherLogCollector network(Context context) {
        final Context app = app(context);
        return CipherLogCollector.of("network", () -> Collections.singletonList(networkText(app)));
    }

    @SuppressLint("MissingPermission") // Checked first; the library adds no permission to the app's manifest.
    static String networkText(Context app) {
        if (app.checkSelfPermission(Manifest.permission.ACCESS_NETWORK_STATE) != PackageManager.PERMISSION_GRANTED) {
            return "unknown (no ACCESS_NETWORK_STATE)";
        }
        ConnectivityManager cm = (ConnectivityManager) app.getSystemService(Context.CONNECTIVITY_SERVICE);
        if (cm == null) return "unknown";
        Network active = cm.getActiveNetwork();
        NetworkCapabilities caps = active == null ? null : cm.getNetworkCapabilities(active);
        if (caps == null) return networkLine(null, false, false);
        String type;
        if (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) {
            type = "wifi";
        } else if (caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) {
            type = "cellular";
        } else if (caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) {
            type = "ethernet";
        } else {
            type = "other";
        }
        boolean expensive = !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED);
        int restrict = Build.VERSION.SDK_INT >= 24 ? cm.getRestrictBackgroundStatus() : 0;
        return networkLine(type, expensive, constrained(expensive, restrict));
    }

    /**
     * Data Saver is a device-wide setting that restricts this app on metered networks only, so the flag describes the
     * current network, as iOS Low Data Mode does: constrained = metered and Data Saver restricts this app.
     */
    static boolean constrained(boolean expensive, int restrictBackgroundStatus) {
        return expensive && restrictBackgroundStatus == ConnectivityManager.RESTRICT_BACKGROUND_STATUS_ENABLED;
    }

    /** {@code wifi · expensive no · constrained no}; {@code none} when there is no network ({@code type} null). */
    static String networkLine(String type, boolean expensive, boolean constrained) {
        if (type == null) return "none";
        return type + " · expensive " + yesNo(expensive) + " · constrained " + yesNo(constrained);
    }

    // ---- storageUsage ----

    /** Sizes of the app's folders and of the default cipherlog directory ({@code noBackupFilesDir/cipherlog}). */
    public static CipherLogCollector storageUsage(Context context) {
        return storageUsage(context, null);
    }

    /** As {@link #storageUsage(Context)}, with the log directory the app passed to {@code Options.directory}. */
    public static CipherLogCollector storageUsage(Context context, final File logDirectory) {
        final Context app = app(context);
        return CipherLogCollector.of("storageUsage", () -> {
            List<String> labels = new ArrayList<>();
            List<File> dirs = new ArrayList<>();
            addDir(labels, dirs, "files", app.getFilesDir());
            addDir(labels, dirs, "cache", app.getCacheDir());
            File noBackup = app.getNoBackupFilesDir();
            addDir(labels, dirs, "no_backup", noBackup);
            File db = app.getDatabasePath("cipherlog-probe");
            addDir(labels, dirs, "databases", db == null ? null : db.getParentFile());
            File logs = logDirectory != null ? logDirectory : noBackup == null ? null : new File(noBackup, "cipherlog");
            addDir(labels, dirs, "logs", logs);
            FolderSizes.Budget budget = new FolderSizes.Budget(FolderSizes.MAX_ENTRIES, FolderSizes.MAX_NANOS,
                    System::nanoTime);
            return Collections.singletonList(storageLine(labels, dirs, budget, FolderSizes.LSTAT));
        });
    }

    private static void addDir(List<String> labels, List<File> dirs, String label, File dir) {
        if (dir == null) return;
        labels.add(label);
        dirs.add(dir);
    }

    static String storageLine(List<String> labels, List<File> dirs, FolderSizes.Budget budget,
            FolderSizes.LinkCheck links) {
        if (dirs.isEmpty()) return "unknown";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < dirs.size(); i++) {
            if (sb.length() > 0) sb.append(" · ");
            File dir = dirs.get(i);
            sb.append(labels.get(i)).append(' ');
            if (dir == null || !dir.exists()) {
                sb.append("none");
            } else if (budget.isOver()) {
                sb.append("not counted");
            } else {
                sb.append(FolderSizes.walk(dir, budget, links).text());
            }
        }
        return sb.toString();
    }
}

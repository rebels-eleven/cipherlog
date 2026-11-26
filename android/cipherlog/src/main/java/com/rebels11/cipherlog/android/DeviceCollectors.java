package com.rebels11.cipherlog.android;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.StatFs;
import com.rebels11.cipherlog.CipherLogCollector;
import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/**
 * The built-in device-block collectors (SPEC.md 2.5, 7.1). They describe the build and the device and never collect
 * names, accounts, ad ids, location, the user-assigned device name, serial numbers or other hardware ids.
 *
 * <ul>
 *   <li>{@code app · <package> · <version name> (<version code>) · installer <installer package or none>}</li>
 *   <li>{@code system · <manufacturer> <model> · Android <release> (API <n>) · patch <security patch> · <ABI>}</li>
 *   <li>{@code locale · <locale> · <language tag>}</li>
 *   <li>{@code disk · <free space, rounded> free}</li>
 * </ul>
 */
public final class DeviceCollectors {
    private DeviceCollectors() {
    }

    /** All four, in the order above. {@code directory} is where free space is measured (the log directory). */
    public static List<CipherLogCollector> defaults(Context context, File directory) {
        List<CipherLogCollector> out = new ArrayList<>();
        out.add(app(context));
        out.add(system());
        out.add(locale());
        out.add(disk(directory));
        return Collections.unmodifiableList(out);
    }

    /** {@code app · com.example · 1.4.2 (42) · installer com.android.vending}. */
    public static CipherLogCollector app(Context context) {
        final Context app = context.getApplicationContext() != null ? context.getApplicationContext() : context;
        return CipherLogCollector.of("app", () -> {
            String pkg = app.getPackageName();
            PackageManager pm = app.getPackageManager();
            PackageInfo info = pm.getPackageInfo(pkg, 0);
            long code = Build.VERSION.SDK_INT >= 28 ? info.getLongVersionCode() : legacyVersionCode(info);
            String version = info.versionName == null ? "-" : info.versionName;
            return Collections.singletonList(pkg + " · " + version + " (" + code + ") · installer " + installer(pm, pkg));
        });
    }

    @SuppressWarnings("deprecation")
    private static long legacyVersionCode(PackageInfo info) {
        return info.versionCode;
    }

    @SuppressWarnings("deprecation")
    private static String installer(PackageManager pm, String pkg) {
        String installer = null;
        try {
            if (Build.VERSION.SDK_INT >= 30) {
                installer = pm.getInstallSourceInfo(pkg).getInstallingPackageName();
            } else {
                installer = pm.getInstallerPackageName(pkg);
            }
        } catch (Exception ignored) {
            // Unknown.
        }
        return installer == null || installer.isEmpty() ? "none" : installer;
    }

    /** {@code system · Google Pixel 9 · Android 16 (API 36) · patch 2026-10-05 · arm64-v8a}. */
    public static CipherLogCollector system() {
        return CipherLogCollector.of("system", () -> {
            String abi = Build.SUPPORTED_ABIS != null && Build.SUPPORTED_ABIS.length > 0 ? Build.SUPPORTED_ABIS[0] : "-";
            String patch = Build.VERSION.SECURITY_PATCH == null || Build.VERSION.SECURITY_PATCH.isEmpty()
                    ? "-" : Build.VERSION.SECURITY_PATCH;
            return Collections.singletonList(model(Build.MANUFACTURER, Build.MODEL) + " · Android " + Build.VERSION.RELEASE
                    + " (API " + Build.VERSION.SDK_INT + ") · patch " + patch + " · " + abi);
        });
    }

    /** {@code Google Pixel 9}; the manufacturer once when the model already starts with it. */
    static String model(String manufacturer, String model) {
        String m = manufacturer == null ? "" : manufacturer.trim();
        String d = model == null ? "" : model.trim();
        if (d.isEmpty()) return m.isEmpty() ? "-" : m;
        if (m.isEmpty() || d.toLowerCase(Locale.ROOT).startsWith(m.toLowerCase(Locale.ROOT))) return d;
        return m + " " + d;
    }

    /** {@code locale · en_GB · en-GB}. */
    public static CipherLogCollector locale() {
        return CipherLogCollector.of("locale", () -> {
            Locale locale = Locale.getDefault();
            return Collections.singletonList(locale + " · " + locale.toLanguageTag());
        });
    }

    /** {@code disk · 23 GB free} for the volume that holds {@code directory}. */
    public static CipherLogCollector disk(final File directory) {
        return CipherLogCollector.of("disk", () -> {
            File dir = directory;
            while (dir != null && !dir.exists()) dir = dir.getParentFile();
            if (dir == null) return Collections.singletonList("unknown");
            return Collections.singletonList(roundedSize(new StatFs(dir.getPath()).getAvailableBytes()) + " free");
        });
    }

    /** Whole GB (10^9 bytes) from 1 GB on, tenths below, as the Swift library does. */
    static String roundedSize(long bytes) {
        double gb = Math.max(0, bytes) / 1_000_000_000.0;
        if (gb >= 1) return Math.round(gb) + " GB";
        return String.format(Locale.ROOT, "%.1f GB", gb);
    }
}

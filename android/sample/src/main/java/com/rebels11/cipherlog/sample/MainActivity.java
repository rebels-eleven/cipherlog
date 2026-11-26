package com.rebels11.cipherlog.sample;

import android.app.Activity;
import android.content.ActivityNotFoundException;
import android.content.Intent;
import android.os.Bundle;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import com.rebels11.cipherlog.android.CipherLog;
import java.io.IOException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** Buttons that log, flush and mail the armored bundle. Plain Views, no UI libraries. */
public final class MainActivity extends Activity {
    private static final String TAG = "Sample";
    private final ExecutorService background = Executors.newSingleThreadExecutor();
    private TextView status;
    private int taps;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        int pad = (int) (16 * getResources().getDisplayMetrics().density);
        LinearLayout column = new LinearLayout(this);
        column.setOrientation(LinearLayout.VERTICAL);
        column.setPadding(pad, pad, pad, pad);

        TextView warning = new TextView(this);
        warning.setText("This sample encrypts its logs to the TEST public key from vectors/test-key.json. Anyone with"
                + " the published test private key can read them. Never ship the test key in an app.");
        warning.setTextColor(0xFFC62828);
        warning.setTextSize(15);
        warning.setPadding(0, 0, 0, pad);
        column.addView(warning);

        addButton(column, "Log info", () -> {
            taps++;
            CipherLog.i(TAG, "tap " + taps);
            show("Logged info (tap " + taps + ").");
        });
        addButton(column, "Log warning", () -> {
            CipherLog.w(TAG, "something looks off");
            show("Logged a warning (written at once).");
        });
        addButton(column, "Log error", () -> {
            CipherLog.e(TAG, "request failed", new IOException("timeout after 10 s"));
            show("Logged an error: the file gets the type and message, no stack trace.");
        });
        addButton(column, "Mail logs to support", this::mailLogs);

        status = new TextView(this);
        status.setPadding(0, pad, 0, 0);
        column.addView(status);
        ScrollView scroll = new ScrollView(this);
        scroll.addView(column);
        setContentView(scroll);
        show(CipherLog.isStarted() && CipherLog.writer().isOn() ? "Writer on." : "Writer off.");
    }

    private void addButton(LinearLayout column, String label, Runnable onTap) {
        Button button = new Button(this);
        button.setText(label);
        button.setOnClickListener(v -> onTap.run());
        column.addView(button, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));
    }

    /** shareIntent writes the bundle, so it runs off the main thread. */
    private void mailLogs() {
        show("Preparing the bundle…");
        background.execute(() -> {
            Intent mail = CipherLog.shareIntent(this, "support@example.com", "cipherlog sample logs");
            runOnUiThread(() -> {
                if (mail == null) {
                    show("No mail app on this device.");
                    return;
                }
                try {
                    startActivity(mail);
                    show("Pick a mail app; the attachment is the armored bundle (.cipherlogs.txt).");
                } catch (ActivityNotFoundException e) {
                    show("No mail app on this device.");
                }
            });
        });
    }

    private void show(String text) {
        status.setText(text);
    }

    @Override
    protected void onDestroy() {
        background.shutdown();
        super.onDestroy();
    }
}

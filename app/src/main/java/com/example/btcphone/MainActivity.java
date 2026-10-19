package com.example.btcphone;

import android.app.Activity;
import android.os.Bundle;
import android.graphics.Typeface;
import android.view.Gravity;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Locale;

public class MainActivity extends Activity {
    private TextView output;
    private Button runButton;

    private static final int ROUNDS_PER_TEST = 100000;
    private static final int TEST_COUNT = 5;

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(24, 28, 24, 24);
        root.setGravity(Gravity.CENTER_HORIZONTAL);
        root.setBackgroundColor(0xFFF4F6F8);

        TextView title = new TextView(this);
        title.setText("BTCPhone 1.2");
        title.setTextSize(28);
        title.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        title.setTextColor(0xFF152238);
        root.addView(title);

        TextView subtitle = new TextView(this);
        subtitle.setText("آزمایش چندمرحله‌ای سرعت SHA-256");
        subtitle.setTextSize(16);
        subtitle.setTextColor(0xFF334155);
        subtitle.setGravity(Gravity.CENTER);
        subtitle.setPadding(0, 12, 0, 20);
        root.addView(subtitle);

        TextView warning = new TextView(this);
        warning.setText("این برنامه استخراج واقعی بیت‌کوین نیست و به استخر استخراج وصل نمی‌شود. سرعت این آزمایش، نرخ هش استخراج بیت‌کوین محسوب نمی‌شود.");
        warning.setTextSize(14);
        warning.setTextColor(0xFF9A3412);
        warning.setGravity(Gravity.CENTER);
        warning.setPadding(12, 12, 12, 12);
        warning.setBackgroundColor(0xFFFFEDD5);
        root.addView(warning);

        runButton = new Button(this);
        runButton.setText("شروع آزمایش ۵ مرحله‌ای");
        root.addView(runButton);

        output = new TextView(this);
        output.setTextSize(15);
        output.setTextColor(0xFF111827);
        output.setPadding(0, 20, 0, 0);
        root.addView(output);

        runButton.setOnClickListener(v -> runTest());
        ScrollView scroll = new ScrollView(this);
        scroll.addView(root);
        setContentView(scroll);
        output.setText("برای شروع، دکمه را بزنید. هر مرحله ۱۰۰٬۰۰۰ دور SHA-256 اجرا می‌کند.");
    }

    private void runTest() {
        runButton.setEnabled(false);
        runButton.setText("آزمایش در حال اجراست...");
        output.setText("لطفاً صبر کنید؛ ۵ مرحله در پس‌زمینه اجرا می‌شود. گوشی را تا پایان در حال استفاده سنگین قرار ندهید.");

        new Thread(() -> {
            long[] times = new long[TEST_COUNT];
            byte[] finalResult = new byte[0];
            String error = null;

            try {
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                byte[] initialData = "BTCPhone SHA-256 benchmark v1.2".getBytes(StandardCharsets.UTF_8);

                // A short warm-up is not included in the reported measurements.
                byte[] warm = initialData;
                for (int i = 0; i < 5000; i++) {
                    warm = digest.digest(warm);
                }

                for (int test = 0; test < TEST_COUNT; test++) {
                    long start = System.nanoTime();
                    byte[] result = initialData;
                    for (int i = 0; i < ROUNDS_PER_TEST; i++) {
                        result = digest.digest(result);
                    }
                    times[test] = System.nanoTime() - start;
                    finalResult = result;
                }
            } catch (Exception e) {
                error = e.getMessage();
            }

            final String failure = error;
            final byte[] hashResult = finalResult;
            runOnUiThread(() -> {
                runButton.setEnabled(true);
                runButton.setText("شروع آزمایش ۵ مرحله‌ای");

                if (failure != null) {
                    output.setText("خطا: " + failure);
                    return;
                }

                long totalNanos = 0L;
                long bestNanos = Long.MAX_VALUE;
                StringBuilder details = new StringBuilder();
                for (int i = 0; i < times.length; i++) {
                    totalNanos += times[i];
                    if (times[i] < bestNanos) bestNanos = times[i];
                    details.append("\nمرحله ").append(i + 1).append(": ")
                        .append(String.format(Locale.US, "%.1f", times[i] / 1_000_000.0))
                        .append(" میلی‌ثانیه");
                }

                double averageNanos = totalNanos / (double) TEST_COUNT;
                double averageMs = averageNanos / 1_000_000.0;
                double hashesPerSecond = ROUNDS_PER_TEST * 1_000_000_000.0 / averageNanos;
                StringBuilder hex = new StringBuilder();
                for (byte b : hashResult) hex.append(String.format(Locale.US, "%02x", b));

                output.setText("آزمایش تمام شد\n"
                    + "تعداد مراحل: " + TEST_COUNT
                    + "\nمحاسبات هر مرحله: " + ROUNDS_PER_TEST
                    + "\nکل محاسبات: " + (long) ROUNDS_PER_TEST * TEST_COUNT
                    + "\nمیانگین زمان هر مرحله: " + String.format(Locale.US, "%.1f", averageMs) + " میلی‌ثانیه"
                    + "\nسرعت آزمایشی SHA-256: " + String.format(Locale.US, "%,.0f", hashesPerSecond) + " هش در ثانیه"
                    + "\nبهترین زمان: " + String.format(Locale.US, "%.1f", bestNanos / 1_000_000.0) + " میلی‌ثانیه"
                    + details
                    + "\n\nهش نهایی: " + hex
                    + "\n\nتوجه: این آزمون زنجیره‌ای SHA-256 است، نه ماینینگ بیت‌کوین و نه پیش‌بینی درآمد.");
            });
        }).start();
    }
}

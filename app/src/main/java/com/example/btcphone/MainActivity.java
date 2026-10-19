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

public class MainActivity extends Activity {
    private TextView output;
    private Button runButton;

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(24, 28, 24, 24);
        root.setGravity(Gravity.CENTER_HORIZONTAL);
        root.setBackgroundColor(0xFFF4F6F8);

        TextView title = new TextView(this);
        title.setText("BTCPhone");
        title.setTextSize(28);
        title.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        title.setTextColor(0xFF152238);
        root.addView(title);

        TextView subtitle = new TextView(this);
        subtitle.setText("آزمایش محاسبه SHA-256 روی گوشی");
        subtitle.setTextSize(16);
        subtitle.setTextColor(0xFF334155);
        subtitle.setGravity(Gravity.CENTER);
        subtitle.setPadding(0, 12, 0, 20);
        root.addView(subtitle);

        TextView warning = new TextView(this);
        warning.setText("این برنامه استخراج واقعی بیت‌کوین نیست و به استخر استخراج وصل نمی‌شود.");
        warning.setTextSize(14);
        warning.setTextColor(0xFF9A3412);
        warning.setGravity(Gravity.CENTER);
        warning.setPadding(12, 12, 12, 12);
        warning.setBackgroundColor(0xFFFFEDD5);
        root.addView(warning);

        runButton = new Button(this);
        runButton.setText("شروع آزمایش");
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
        output.setText("برای شروع، دکمه را بزنید.");
    }

    private void runTest() {
        runButton.setEnabled(false);
        long start = System.nanoTime();
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] data = "BTCPhone test".getBytes(StandardCharsets.UTF_8);
            int rounds = 100000;
            byte[] result = data;
            for (int i = 0; i < rounds; i++) {
                result = digest.digest(result);
            }
            long elapsedMs = (System.nanoTime() - start) / 1_000_000;
            StringBuilder hex = new StringBuilder();
            for (byte b : result) hex.append(String.format("%02x", b));
            output.setText("آزمایش تمام شد\nتعداد محاسبات: " + rounds
                + "\nزمان: " + elapsedMs + " میلی‌ثانیه"
                + "\nهش آخر: " + hex
                + "\n\nاین فقط آزمون پردازشی است، نه استخراج یا درآمد بیت‌کوین.");
        } catch (Exception e) {
            output.setText("خطا: " + e.getMessage());
        } finally {
            runButton.setEnabled(true);
        }
    }
}

package com.example.btcphone;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.graphics.Typeface;
import android.view.Gravity;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.BufferedWriter;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.RoundingMode;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Locale;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLParameters;

public class MainActivity extends Activity {
    private EditText hostInput, portInput, workerInput, passwordInput;
    private CheckBox tlsCheck;
    private Button connectButton, stopButton, testButton;
    private TextView status, output;

    private final AtomicBoolean running = new AtomicBoolean(false);
    private volatile Socket socket;
    private volatile BufferedWriter writer;
    private volatile Job currentJob;
    private volatile double shareDifficulty = 1.0;
    private volatile String extranonce1 = "";
    private volatile int extranonce2Size = 4;
    private volatile String workerName = "";
    private volatile long hashesDone = 0;
    private volatile long submitted = 0;
    private volatile long accepted = 0;
    private volatile long rejected = 0;
    private volatile long submissionErrors = 0;
    private volatile long unconfirmed = 0;
    private final Set<Integer> pendingSubmitIds = Collections.synchronizedSet(new HashSet<>());
    private volatile long startTime = 0;
    private volatile int nextSubmitId = 100;
    private volatile boolean authorized = false;
    private volatile String latestStatus = "آماده";
    private Thread networkThread;
    private Thread miningThread;
    // Reuse the SHA-256 engine on the mining thread to avoid allocating one per nonce.
    private final ThreadLocal<MessageDigest> sha256Digest = new ThreadLocal<>();

    private static final BigInteger DIFF1_TARGET = new BigInteger(
        "00000000FFFF0000000000000000000000000000000000000000000000000000", 16
    );

    private static class Job {
        String id, prevHash, coinb1, coinb2, version, nbits, ntime;
        String[] branches;
        boolean clean;
        Job(String id, String prevHash, String coinb1, String coinb2, String[] branches,
            String version, String nbits, String ntime, boolean clean) {
            this.id=id; this.prevHash=prevHash; this.coinb1=coinb1; this.coinb2=coinb2;
            this.branches=branches; this.version=version; this.nbits=nbits;
            this.ntime=ntime; this.clean=clean;
        }
    }

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);

        ScrollView scroll = new ScrollView(this);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(22, 24, 22, 24);
        root.setBackgroundColor(0xFFF4F6F8);

        TextView title = new TextView(this);
        title.setText("BTCPhone 1.3");
        title.setTextSize(28);
        title.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        title.setTextColor(0xFF152238);
        root.addView(title);

        TextView intro = new TextView(this);
        intro.setText("آزمایش SHA-256 و اتصال آزمایشی به استخرهای Stratum V1 مخصوص SHA-256");
        intro.setTextSize(15);
        intro.setTextColor(0xFF334155);
        intro.setPadding(0, 8, 0, 14);
        root.addView(intro);

        TextView warning = new TextView(this);
        warning.setText("هشدار: استخراج با گوشی معمولاً درآمد ناچیز یا صفر دارد و می‌تواند گوشی را داغ و باتری را فرسوده کند. فقط از استخر مورداعتماد استفاده کن. اتصال بدون TLS رمزگذاری نشده است. این نسخه آزمایشی است و قبل از استفاده جدی باید با استخر واقعی آزموده شود.");
        warning.setTextColor(0xFF9A3412);
        warning.setTextSize(13);
        warning.setPadding(12, 12, 12, 12);
        warning.setBackgroundColor(0xFFFFEDD5);
        root.addView(warning);

        hostInput = field("آدرس استخر (مثلاً stratum.example.com)", false);
        portInput = field("درگاه استخر (Port)", false);
        workerInput = field("نام کارگر / Worker (طبق تنظیمات استخر)", false);
        passwordInput = field("رمز کارگر (اغلب x؛ طبق استخر)", true);
        root.addView(hostInput);
        root.addView(portInput);
        root.addView(workerInput);
        root.addView(passwordInput);

        tlsCheck = new CheckBox(this);
        tlsCheck.setText("اتصال TLS امن (در صورت پشتیبانی استخر)");
        tlsCheck.setChecked(true);
        tlsCheck.setTextColor(0xFF111827);
        root.addView(tlsCheck);

        connectButton = new Button(this);
        connectButton.setText("اتصال و شروع استخراج آزمایشی");
        root.addView(connectButton);

        stopButton = new Button(this);
        stopButton.setText("توقف");
        stopButton.setEnabled(false);
        root.addView(stopButton);

        testButton = new Button(this);
        testButton.setText("اجرای آزمایش محلی ۵ مرحله‌ای");
        root.addView(testButton);

        status = new TextView(this);
        status.setTextSize(16);
        status.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        status.setTextColor(0xFF152238);
        status.setPadding(0, 18, 0, 8);
        status.setText("وضعیت: آماده");
        root.addView(status);

        output = new TextView(this);
        output.setTextSize(14);
        output.setTextColor(0xFF111827);
        output.setText("برای اتصال باید اطلاعات استخر و Worker خودت را وارد کنی. این برنامه هیچ استخر یا کیف پولی از پیش تنظیم نکرده است.");
        root.addView(output);

        connectButton.setOnClickListener(v -> startMining());
        stopButton.setOnClickListener(v -> stopMining("به درخواست کاربر متوقف شد."));
        testButton.setOnClickListener(v -> runLocalBenchmark());
        scroll.addView(root);
        setContentView(scroll);
    }

    private EditText field(String hint, boolean password) {
        EditText e = new EditText(this);
        e.setSingleLine(true);
        e.setTextSize(14);
        e.setHint(hint);
        e.setPadding(12, 8, 12, 8);
        if (password) e.setInputType(1 | 0x80);
        return e;
    }

    private void startMining() {
        String host = hostInput.getText().toString().trim();
        String portText = portInput.getText().toString().trim();
        String worker = workerInput.getText().toString().trim();
        String password = passwordInput.getText().toString();
        if (host.isEmpty() || portText.isEmpty() || worker.isEmpty()) {
            Toast.makeText(this, "آدرس، درگاه و نام Worker را وارد کن.", Toast.LENGTH_LONG).show();
            return;
        }
        final int port;
        try {
            port = Integer.parseInt(portText);
            if (port < 1 || port > 65535) throw new NumberFormatException();
        } catch (Exception e) {
            Toast.makeText(this, "شماره درگاه معتبر نیست.", Toast.LENGTH_LONG).show();
            return;
        }
        workerName = worker;
        Intent serviceIntent = new Intent(this, MiningForegroundService.class);
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) startForegroundService(serviceIntent);
        else startService(serviceIntent);
        running.set(true);
        authorized = false;
        hashesDone = 0;
        submitted = 0;
        accepted = 0;
        rejected = 0;
        submissionErrors = 0;
        unconfirmed = 0;
        pendingSubmitIds.clear();
        startTime = System.nanoTime();
        currentJob = null;
        connectButton.setEnabled(false);
        stopButton.setEnabled(true);
        testButton.setEnabled(false);
        setStatus("در حال اتصال به استخر...");
        append("در حال اتصال به " + host + ":" + port + (tlsCheck.isChecked() ? " با TLS" : " بدون TLS") + "\n");
        networkThread = new Thread(() -> networkLoop(host, port, worker, password, tlsCheck.isChecked()), "BTCPhone-network");
        networkThread.start();
    }

    private void networkLoop(String host, int port, String worker, String password, boolean tls) {
        while (running.get()) {
            Socket activeSocket = null;
            try {
                Socket plain = new Socket();
                plain.connect(new InetSocketAddress(host, port), 15000);
                Socket s;
                if (tls) {
                    SSLSocket secure = (SSLSocket) ((SSLSocketFactory) SSLSocketFactory.getDefault()).createSocket(plain, host, port, true);
                    SSLParameters sslParameters = secure.getSSLParameters();
                    sslParameters.setEndpointIdentificationAlgorithm("HTTPS");
                    secure.setSSLParameters(sslParameters);
                    secure.startHandshake();
                    s = secure;
                } else {
                    s = plain;
                }
                activeSocket = s;
                socket = s;
                s.setSoTimeout(1000);
                BufferedReader reader = new BufferedReader(new InputStreamReader(s.getInputStream(), StandardCharsets.UTF_8));
                writer = new BufferedWriter(new OutputStreamWriter(s.getOutputStream(), StandardCharsets.UTF_8));
                currentJob = null;
                authorized = false;
                sendJson("{\"id\":1,\"method\":\"mining.subscribe\",\"params\":[\"BTCPhone/1.3\"]}");
                long lastUi = 0;
                long lastDetailedLog = 0;
                append("اتصال برقرار شد؛ درخواست subscribe ارسال شد.\n");
                while (running.get()) {
                    String line = null;
                    boolean timedOut = false;
                    try {
                        line = reader.readLine();
                    } catch (java.net.SocketTimeoutException timeout) {
                        timedOut = true;
                    }
                    // readLine() returns null on EOF; a timeout is handled separately above.
                    if (line == null && !timedOut) {
                        throw new Exception("استخر اتصال را بست (EOF)");
                    }
                    if (line != null) {
                        try {
                            JSONObject msg = new JSONObject(line);
                            Object idObj = msg.opt("id");
                            if (idObj instanceof Number && ((Number) idObj).intValue() == 1) {
                                JSONArray result = msg.optJSONArray("result");
                                if (result == null || result.length() < 3) throw new Exception("پاسخ subscribe نامعتبر است");
                                extranonce1 = result.getString(1);
                                extranonce2Size = result.getInt(2);
                                if (extranonce2Size < 1 || extranonce2Size > 16) throw new Exception("اندازه extranonce2 پشتیبانی نمی‌شود");
                                sendJson("{\"id\":2,\"method\":\"mining.authorize\",\"params\":[" + JSONObject.quote(worker) + "," + JSONObject.quote(password) + "]}");
                                append("اشتراک Stratum دریافت شد؛ در حال احراز هویت Worker...\n");
                            } else if (idObj instanceof Number && ((Number) idObj).intValue() == 2) {
                                authorized = msg.optBoolean("result", false);
                                if (!authorized) throw new Exception("استخر Worker را نپذیرفت؛ نام کارگر/رمز را بررسی کن");
                                startTime = System.nanoTime();
                                setStatus("متصل و مجاز؛ منتظر کار استخر");
                                append("احراز هویت موفق شد. منتظر mining.notify هستیم.\n");
                                if (miningThread == null || !miningThread.isAlive()) {
                                    miningThread = new Thread(this::miningLoop, "BTCPhone-miner");
                                    miningThread.start();
                                }
                            } else if (idObj instanceof Number && ((Number) idObj).intValue() >= 100) {
                                int responseId = ((Number) idObj).intValue();
                                if (!pendingSubmitIds.remove(responseId)) {
                                    append("پاسخ با شناسه ناشناخته/تکراری نادیده گرفته شد: " + responseId + "\n");
                                } else {
                                    Object resultValue = msg.opt("result");
                                    Object errorValue = msg.opt("error");
                                    boolean hasError = errorValue != null && errorValue != JSONObject.NULL;
                                    if (resultValue instanceof Boolean) {
                                        if ((Boolean) resultValue && !hasError) {
                                            accepted++;
                                            append("استخر سهم را پذیرفت. مجموع پذیرفته‌شده: " + accepted + "\n");
                                        } else {
                                            rejected++;
                                            append("استخر سهم را رد کرد. مجموع ردشده: " + rejected + (hasError ? " | خطا: " + errorValue : "") + "\n");
                                        }
                                    } else if (hasError) {
                                        rejected++;
                                        append("استخر درخواست سهم را با خطا رد کرد. مجموع ردشده: " + rejected + " | خطا: " + errorValue + "\n");
                                    } else {
                                        unconfirmed++;
                                        append("پاسخ سهم قالب معتبر ندارد؛ ردشده محسوب نشد. شناسه: " + responseId + "\n");
                                    }
                                }
                            } else {
                                String methodName = msg.optString("method", "");
                                JSONArray params = msg.optJSONArray("params");
                                if ("mining.set_difficulty".equals(methodName) && params != null && params.length() > 0) {
                                    double d = params.getDouble(0);
                                    if (d > 0 && Double.isFinite(d)) shareDifficulty = d;
                                    append("سختی سهم اعلام‌شده استخر: " + shareDifficulty + "\n");
                                } else if ("mining.set_extranonce".equals(methodName) && params != null && params.length() >= 2) {
                                    String newExtranonce1 = params.getString(0);
                                    int newExtranonce2Size = params.getInt(1);
                                    if ((newExtranonce1.length() & 1) != 0 || newExtranonce2Size < 1 || newExtranonce2Size > 16) {
                                        throw new Exception("پیام set_extranonce نامعتبر است");
                                    }
                                    hexToBytes(newExtranonce1);
                                    extranonce1 = newExtranonce1;
                                    extranonce2Size = newExtranonce2Size;
                                    currentJob = null;
                                    append("پارامترهای extranonce از استخر به‌روزرسانی شد؛ منتظر کار جدید هستیم.\n");
                                } else if ("mining.notify".equals(methodName) && params != null && params.length() >= 9) {
                                    String[] branches = new String[params.getJSONArray(4).length()];
                                    JSONArray b = params.getJSONArray(4);
                                    for (int i = 0; i < b.length(); i++) branches[i] = b.getString(i);
                                    Job job = new Job(params.getString(0), params.getString(1), params.getString(2),
                                        params.getString(3), branches, params.getString(5), params.getString(6),
                                        params.getString(7), params.getBoolean(8));
                                    currentJob = job;
                                    append("کار جدید استخر دریافت شد: " + job.id + "\n");
                                    setStatus("کار استخر دریافت شد؛ آماده محاسبه");
                                }
                            }
                        } catch (Exception parseError) {
                            append("پیام/خطای استخر: " + parseError.getMessage() + "\n");
                            if (line.contains("\"id\":2") || line.contains("\"id\": 2")) throw parseError;
                        }
                    }
                    long now = System.nanoTime();
                    if (now - lastUi > 2_000_000_000L && authorized) {
                        lastUi = now;
                        double seconds = (now - startTime) / 1_000_000_000.0;
                        double rate = seconds > 0 ? hashesDone / seconds : 0;
                        Job visibleJob = currentJob;
                        String jobId = visibleJob == null ? "ندارد" : visibleJob.id;
                        setStatus(String.format(Locale.US, "هش: %,.0f H/s | کل هش: %,d | ارسال: %d | قبول: %d | رد: %d | بی‌پاسخ: %d", rate, hashesDone, submitted, accepted, rejected, unconfirmed + pendingSubmitIds.size()));
                        if (now - lastDetailedLog > 10_000_000_000L) {
                            lastDetailedLog = now;
                            append(String.format(Locale.US, "گزارش زنده: هش کل %,d | سرعت %,.0f H/s | سختی سهم %.4f | ارسال موفق %d | پذیرفته %d | ردشده %d | ارسال ناموفق %d | بی‌پاسخ/نامشخص %d | در انتظار پاسخ %d | شناسه کار %s\nتخمین آماری زمان یک سهم با سختی فعلی: %s (ممکن است سال‌ها باشد؛ زمان پیدا کردن بلوک نیست و شمارش معکوس نیست).\n", hashesDone, rate, shareDifficulty, submitted, accepted, rejected, submissionErrors, unconfirmed, pendingSubmitIds.size(), jobId, expectedShareTime(rate, shareDifficulty)));
                        }
                    }
                }
            } catch (Exception e) {
                if (running.get()) {
                    append("اتصال قطع شد: " + e.getMessage() + "\n");
                    setStatus("اتصال قطع شد؛ تلاش مجدد انجام می‌شود");
                }
            } finally {
                authorized = false;
                currentJob = null;
                synchronized (pendingSubmitIds) {
                    if (!pendingSubmitIds.isEmpty()) {
                        long lost = pendingSubmitIds.size();
                        unconfirmed += lost;
                        pendingSubmitIds.clear();
                        append("اتصال پایان یافت؛ " + lost + " سهم بدون پاسخ تأیید/رد ماندند.\n");
                    }
                }
                try { if (activeSocket != null) activeSocket.close(); } catch (Exception ignored) {}
                if (socket == activeSocket) socket = null;
                writer = null;
            }
            if (running.get()) {
                append("تلاش برای اتصال مجدد تا ۳ ثانیه دیگر...\n");
                setStatus("در انتظار اتصال مجدد...");
                try { Thread.sleep(3000); } catch (InterruptedException ignored) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        }
        running.set(false);
        authorized = false;
        try { if (socket != null) socket.close(); } catch (Exception ignored) {}
        socket = null;
        writer = null;
        runOnUiThread(() -> {
            connectButton.setEnabled(true);
            stopButton.setEnabled(false);
            testButton.setEnabled(true);
        });
    }

    private synchronized void sendJson(String json) throws Exception {
        if (writer == null) throw new Exception("اتصال آماده نیست");
        writer.write(json);
        writer.write("\n");
        writer.flush();
    }

    private void miningLoop() {
        int observedExtranonce2Size = extranonce2Size;
        String observedExtranonce1 = extranonce1;
        byte[] extranonce2 = new byte[observedExtranonce2Size];
        while (running.get()) {
            if (!authorized) {
                try { Thread.sleep(150); } catch (InterruptedException ignored) { Thread.currentThread().interrupt(); break; }
                continue;
            }
            // Stratum may update extranonce parameters after subscription. Reset the counter
            // and rebuild the coinbase when those parameters change.
            if (observedExtranonce2Size != extranonce2Size || !observedExtranonce1.equals(extranonce1)) {
                observedExtranonce2Size = extranonce2Size;
                observedExtranonce1 = extranonce1;
                extranonce2 = new byte[observedExtranonce2Size];
            }
            Job job = currentJob;
            if (job == null) {
                try { Thread.sleep(150); } catch (InterruptedException ignored) {}
                continue;
            }
            try {
                boolean restart = false;
                // The coinbase/merkle root stays the same for this extranonce2 batch.
                // Compute it once instead of recalculating it for every nonce.
                String batchExtranonce1 = observedExtranonce1;
                byte[] merkleRoot = buildMerkleRoot(job, extranonce2, batchExtranonce1);
                double batchDifficulty = shareDifficulty;
                BigInteger target = new BigDecimal(DIFF1_TARGET)
                    .divide(BigDecimal.valueOf(Math.max(batchDifficulty, 0.00000001)), 0, RoundingMode.DOWN)
                    .toBigInteger();
                boolean everyHashQualifies = target.bitLength() > 256;
                byte[] targetBytes = everyHashQualifies ? null : toFixed32(target);
                // Performance: reuse the 80-byte header and update only the 4-byte nonce each iteration.
                byte[] header = buildHeader(job, merkleRoot, 0);
                for (long nonce = 0; nonce < 100000L && running.get() && authorized; nonce++) {
                    if (currentJob != job || Double.compare(shareDifficulty, batchDifficulty) != 0) {
                        restart = true;
                        break;
                    }
                    int n = (int) nonce;
                    header[76] = (byte) n;
                    header[77] = (byte) (n >>> 8);
                    header[78] = (byte) (n >>> 16);
                    header[79] = (byte) (n >>> 24);
                    byte[] hash = doubleSha(header);
                    hashesDone++;
                    if (everyHashQualifies || hashMeetsTarget(hash, targetBytes)) {
                        String nonceHex = String.format(Locale.US, "%08x", nonce);
                        String en2 = bytesToHex(extranonce2);
                        int submitId = nextSubmitId++;
                        String submit = "{\"id\":" + submitId + ",\"method\":\"mining.submit\",\"params\":["
                            + JSONObject.quote(workerName) + "," + JSONObject.quote(job.id) + ","
                            + JSONObject.quote(en2) + "," + JSONObject.quote(job.ntime) + ","
                            + JSONObject.quote(nonceHex) + "]}";
                        pendingSubmitIds.add(submitId);
                        try {
                            sendJson(submit);
                            submitted++;
                            append("درخواست سهم ارسال شد؛ nonce=" + nonceHex + " | ارسال موفق: " + submitted + " | در انتظار پاسخ: " + pendingSubmitIds.size() + "\n");
                        } catch (Exception sendError) {
                            pendingSubmitIds.remove(submitId);
                            submissionErrors++;
                            append("ارسال سهم ناموفق بود: " + sendError.getMessage() + " | مجموع خطای ارسال: " + submissionErrors + "\n");
                            throw sendError;
                        }
                        increment(extranonce2);
                        restart = true;
                        break;
                    }
                }
                if (!restart && running.get() && currentJob == job) increment(extranonce2);
                if (currentJob == job) Thread.yield();
            } catch (Exception e) {
                append("خطای محاسبه: " + e.getMessage() + "\n");
                try { Thread.sleep(250); } catch (InterruptedException ignored) {}
            }
        }
    }

    // Convert a non-negative target into exactly 32 big-endian bytes.
    private byte[] toFixed32(BigInteger value) {
        byte[] raw = value.toByteArray();
        byte[] out = new byte[32];
        int src = Math.max(0, raw.length - 32);
        int len = Math.min(32, raw.length);
        System.arraycopy(raw, src, out, 32 - len, len);
        return out;
    }

    // Bitcoin interprets the displayed hash in reverse byte order. Compare bytes directly
    // to avoid allocating a BigInteger for every nonce.
    private boolean hashMeetsTarget(byte[] hash, byte[] targetBytes) {
        for (int i = 0; i < 32; i++) {
            int hashByte = hash[31 - i] & 0xff;
            int targetByte = targetBytes[i] & 0xff;
            if (hashByte < targetByte) return true;
            if (hashByte > targetByte) return false;
        }
        return true;
    }

    private byte[] buildMerkleRoot(Job job, byte[] extranonce2, String batchExtranonce1) throws Exception {
        byte[] coinbase = hexToBytes(job.coinb1 + batchExtranonce1 + bytesToHex(extranonce2) + job.coinb2);
        byte[] merkle = doubleSha(coinbase);
        for (String branch : job.branches) merkle = doubleSha(concat(merkle, hexToBytes(branch)));
        return merkle;
    }

    private byte[] buildHeader(Job job, byte[] merkleRoot, long nonce) throws Exception {
        byte[] prev = reverseWords4(hexToBytes(job.prevHash));
        // Stratum V1 merkle calculation already yields header byte order; do not reverse it.
        byte[] root = merkleRoot;
        byte[] version = reverse(hexToBytes(job.version));
        byte[] ntime = reverse(hexToBytes(job.ntime));
        byte[] nbits = reverse(hexToBytes(job.nbits));
        byte[] nonceBytes = new byte[] {(byte) nonce, (byte)(nonce >>> 8), (byte)(nonce >>> 16), (byte)(nonce >>> 24)};
        byte[] header = concat(concat(concat(concat(concat(version, prev), root), ntime), nbits), nonceBytes);
        if (header.length != 80) throw new Exception("طول هدر نامعتبر: " + header.length);
        return header;
    }

    private byte[] doubleSha(byte[] data) throws Exception {
        MessageDigest d = sha256Digest.get();
        if (d == null) {
            d = MessageDigest.getInstance("SHA-256");
            sha256Digest.set(d);
        }
        // MessageDigest.digest() resets the instance after each digest.
        return d.digest(d.digest(data));
    }

    private byte[] hexToBytes(String hex) throws Exception {
        if (hex == null || (hex.length() & 1) != 0) throw new Exception("رشته hex نامعتبر");
        byte[] out = new byte[hex.length() / 2];
        for (int i=0;i<out.length;i++) out[i]=(byte)Integer.parseInt(hex.substring(i*2,i*2+2),16);
        return out;
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder b = new StringBuilder();
        for (byte v : bytes) b.append(String.format(Locale.US, "%02x", v & 255));
        return b.toString();
    }

    private byte[] reverse(byte[] bytes) {
        byte[] out = bytes.clone();
        for (int i=0,j=out.length-1;i<j;i++,j--) { byte t=out[i]; out[i]=out[j]; out[j]=t; }
        return out;
    }

    private byte[] reverseWords4(byte[] bytes) {
        byte[] out = bytes.clone();
        for (int p=0;p+3<out.length;p+=4) {
            byte t=out[p]; out[p]=out[p+3]; out[p+3]=t;
            t=out[p+1]; out[p+1]=out[p+2]; out[p+2]=t;
        }
        return out;
    }

    private byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length+b.length];
        System.arraycopy(a,0,out,0,a.length);
        System.arraycopy(b,0,out,a.length,b.length);
        return out;
    }

    private void increment(byte[] bytes) {
        for (int i=bytes.length-1;i>=0;i--) {
            bytes[i]++;
            if (bytes[i] != 0) break;
        }
    }

    private void runLocalBenchmark() {
        testButton.setEnabled(false);
        connectButton.setEnabled(false);
        setStatus("آزمایش محلی در حال اجرا...");
        new Thread(() -> {
            try {
                long[] times = new long[5];
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                byte[] initial = "BTCPhone test".getBytes(StandardCharsets.UTF_8);
                byte[] result = initial;
                for (int i=0;i<5000;i++) result=digest.digest(result);
                for (int t=0;t<5;t++) {
                    result = initial;
                    long start = System.nanoTime();
                    for (int i=0;i<100000;i++) result=digest.digest(result);
                    times[t] = System.nanoTime()-start;
                }
                long total=0;
                for(long n:times) total+=n;
                double averageMs=total/5.0/1_000_000.0;
                double rate=100000.0/(total/5.0/1_000_000_000.0);
                final String message=String.format(Locale.US,
                    "آزمایش محلی پایان یافت\n۵ مرحله × ۱۰۰٬۰۰۰ = ۵۰۰٬۰۰۰ دور\nمیانگین زمان هر مرحله: %.1f میلی‌ثانیه\nسرعت آزمون زنجیره‌ای: %,.0f H/s\n\nاین نرخ، نرخ استخراج واقعی بیت‌کوین نیست.", averageMs, rate);
                runOnUiThread(() -> { output.setText(message); setStatus("آزمایش محلی تمام شد"); testButton.setEnabled(true); connectButton.setEnabled(true); });
            } catch(Exception e) {
                runOnUiThread(() -> { output.setText("خطا: "+e.getMessage()); testButton.setEnabled(true); connectButton.setEnabled(true); });
            }
        }, "BTCPhone-benchmark").start();
    }

    private String expectedShareTime(double rate, double difficulty) {
        if (rate <= 0 || difficulty <= 0 || !Double.isFinite(rate) || !Double.isFinite(difficulty)) return "قابل محاسبه نیست";
        double seconds = 4294967296.0 * difficulty / rate;
        if (seconds < 60) return String.format(Locale.US, "%.1f ثانیه", seconds);
        if (seconds < 3600) return String.format(Locale.US, "%.1f دقیقه", seconds / 60.0);
        if (seconds < 86400) return String.format(Locale.US, "%.1f ساعت", seconds / 3600.0);
        if (seconds < 31557600) return String.format(Locale.US, "%.1f روز", seconds / 86400.0);
        return String.format(Locale.US, "%.1f سال", seconds / 31557600.0);
    }

    private void stopMining(String reason) {
        running.set(false);
        authorized = false;
        currentJob = null;
        try { if (socket != null) socket.close(); } catch (Exception ignored) {}
        try { stopService(new Intent(this, MiningForegroundService.class)); } catch (Exception ignored) {}
        setStatus(reason);
        append(reason + "\n");
        connectButton.setEnabled(true);
        stopButton.setEnabled(false);
        testButton.setEnabled(true);
    }

    private void setStatus(String text) {
        runOnUiThread(() -> status.setText("وضعیت: " + text));
    }

    private void append(String text) {
        runOnUiThread(() -> {
            String old = output.getText().toString();
            if (old.length() > 5000) old = old.substring(old.length()-3000);
            output.setText(old + text);
        });
    }

    @Override
    protected void onDestroy() {
        getWindow().clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
        super.onDestroy();
    }
}

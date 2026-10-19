package com.example.btcphone;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Intent;
import android.os.Build;
import android.os.IBinder;

/** Visible foreground indicator for a user-started experimental session. */
public class MiningForegroundService extends Service {
    private static final String CHANNEL_ID = "btcphone_session";
    private static final int NOTIFICATION_ID = 7301;

    @Override public void onCreate() {
        super.onCreate();
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel channel = new NotificationChannel(
                CHANNEL_ID, "BTCPhone session", NotificationManager.IMPORTANCE_LOW);
            channel.setDescription("Shows when a user-started BTCPhone test session is active.");
            NotificationManager manager = getSystemService(NotificationManager.class);
            if (manager != null) manager.createNotificationChannel(channel);
        }
        Notification.Builder builder = Build.VERSION.SDK_INT >= Build.VERSION_CODES.O
            ? new Notification.Builder(this, CHANNEL_ID) : new Notification.Builder(this);
        builder.setContentTitle("BTCPhone session active")
            .setContentText("Experimental session running; open BTCPhone to stop it.")
            .setSmallIcon(android.R.drawable.stat_notify_sync)
            .setOngoing(true)
            .setCategory(Notification.CATEGORY_SERVICE);
        startForeground(NOTIFICATION_ID, builder.build());
    }

    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        return START_STICKY;
    }

    @Override public IBinder onBind(Intent intent) { return null; }
}

package com.internet.app;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.os.Build;
import android.os.IBinder;

public class HostingService extends Service {
    private static final String CHANNEL = "hosting";
    private static final int NOTIFICATION_ID = 1;

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        String name = intent != null ? intent.getStringExtra("name") : null;
        if (name == null || name.isEmpty()) {
            name = "your site";
        }

        NotificationManager manager = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
        if (Build.VERSION.SDK_INT >= 26 && manager != null) {
            manager.createNotificationChannel(
                    new NotificationChannel(CHANNEL, "Hosting", NotificationManager.IMPORTANCE_LOW));
        }

        Intent open = new Intent(this, InternetActivity.class);
        open.setFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP | Intent.FLAG_ACTIVITY_CLEAR_TOP);
        PendingIntent pending = PendingIntent.getActivity(this, 0, open,
                PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);

        Notification.Builder builder = Build.VERSION.SDK_INT >= 26
                ? new Notification.Builder(this, CHANNEL)
                : new Notification.Builder(this);
        builder.setContentTitle("Internet")
                .setContentText("Hosting internet://" + name + "/")
                .setSmallIcon(android.R.drawable.stat_sys_upload)
                .setContentIntent(pending)
                .setOngoing(true);
        Notification notification = builder.build();

        if (Build.VERSION.SDK_INT >= 29) {
            startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC);
        } else {
            startForeground(NOTIFICATION_ID, notification);
        }
        return START_NOT_STICKY;
    }

    @Override
    public void onDestroy() {
        stopForeground(true);
        super.onDestroy();
    }
}

package com.internet.app;

import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.VibrationEffect;
import android.os.Vibrator;

import org.libsdl.app.SDLActivity;

public class InternetActivity extends SDLActivity {
    private String pendingLink = "";

    @Override
    protected String[] getLibraries() {
        return new String[] {"SDL3", "main"};
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        captureLink(getIntent());
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        captureLink(intent);
    }

    private synchronized void captureLink(Intent intent) {
        if (intent == null || !Intent.ACTION_VIEW.equals(intent.getAction())) {
            return;
        }
        Uri data = intent.getData();
        if (data != null) {
            pendingLink = data.toString();
        }
    }

    public synchronized String takeLaunchLink() {
        String link = pendingLink;
        pendingLink = "";
        return link;
    }

    public void shareText(final String text) {
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                Intent send = new Intent(Intent.ACTION_SEND);
                send.setType("text/plain");
                send.putExtra(Intent.EXTRA_TEXT, text);
                startActivity(Intent.createChooser(send, "Share link"));
            }
        });
    }

    public void vibrate(int milliseconds) {
        Vibrator vibrator = (Vibrator) getSystemService(VIBRATOR_SERVICE);
        if (vibrator == null || !vibrator.hasVibrator()) {
            return;
        }
        if (Build.VERSION.SDK_INT >= 26) {
            vibrator.vibrate(VibrationEffect.createOneShot(milliseconds, VibrationEffect.DEFAULT_AMPLITUDE));
        } else {
            vibrator.vibrate(milliseconds);
        }
    }

    public void setHosting(final boolean active, final String name) {
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                Intent service = new Intent(InternetActivity.this, HostingService.class);
                if (!active) {
                    stopService(service);
                    return;
                }
                if (Build.VERSION.SDK_INT >= 33
                        && checkSelfPermission("android.permission.POST_NOTIFICATIONS") != PackageManager.PERMISSION_GRANTED) {
                    requestPermissions(new String[] {"android.permission.POST_NOTIFICATIONS"}, 1);
                }
                service.putExtra("name", name);
                if (Build.VERSION.SDK_INT >= 26) {
                    startForegroundService(service);
                } else {
                    startService(service);
                }
            }
        });
    }
}

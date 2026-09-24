package com.internet.app;

import org.libsdl.app.SDLActivity;

public class InternetActivity extends SDLActivity {
    @Override
    protected String[] getLibraries() {
        return new String[] {"SDL3", "main"};
    }
}

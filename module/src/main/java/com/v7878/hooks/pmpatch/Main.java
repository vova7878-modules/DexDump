package com.v7878.hooks.pmpatch;

import android.util.Log;

import com.v7878.r8.annotations.DoNotObfuscate;
import com.v7878.r8.annotations.DoNotObfuscateType;
import com.v7878.r8.annotations.DoNotShrink;
import com.v7878.r8.annotations.DoNotShrinkType;
import com.v7878.zygisk.ZygoteLoader;

@DoNotShrinkType
@DoNotObfuscateType
public class Main {
    public static String TAG = "DEX_DUMP";

    @DoNotShrink
    @DoNotObfuscate
    public static void premain() {
        // nop
    }

    @SuppressWarnings("ConfusingMainMethod")
    @DoNotShrink
    @DoNotObfuscate
    public static void main() {
        Log.i(TAG, "Injected into " + ZygoteLoader.getPackageName());
        try {
            ClassLoaderInit.init();
        } catch (Throwable th) {
            Log.e(TAG, "Exception", th);
        }
        Log.i(TAG, "Done");
    }
}

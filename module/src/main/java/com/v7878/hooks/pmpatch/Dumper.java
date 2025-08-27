package com.v7878.hooks.pmpatch;

import static com.v7878.hooks.pmpatch.Main.TAG;
import static com.v7878.unsafe.access.AccessLinker.FieldAccessKind.INSTANCE_GETTER;

import android.util.Log;

import com.v7878.r8.annotations.DoNotOptimize;
import com.v7878.r8.annotations.DoNotShrink;
import com.v7878.r8.annotations.DoNotShrinkType;
import com.v7878.unsafe.DexFileUtils;
import com.v7878.unsafe.access.AccessLinker;
import com.v7878.unsafe.access.AccessLinker.FieldAccess;
import com.v7878.vmtools.DexFileDump;
import com.v7878.zygisk.ZygoteLoader;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import dalvik.system.BaseDexClassLoader;
import dalvik.system.DexFile;

public class Dumper {
    @DoNotShrinkType
    @DoNotOptimize
    private abstract static class AccessI {
        @FieldAccess(kind = INSTANCE_GETTER, klass = "dalvik.system.BaseDexClassLoader", name = "pathList")
        abstract Object pathList(BaseDexClassLoader instance);

        @FieldAccess(kind = INSTANCE_GETTER, klass = "dalvik.system.DexPathList", name = "dexElements")
        abstract Object[] dexElements(Object instance);

        @FieldAccess(kind = INSTANCE_GETTER, klass = "dalvik.system.DexPathList$Element", name = "dexFile")
        abstract DexFile dexFile(Object instance);

        static final AccessI INSTANCE = AccessLinker.generateImpl(AccessI.class);
    }

    static class Holder {
        // lazy init - initialization occurs when everything is ready
        static final File DUMP_DIR;

        static {
            //noinspection DataFlowIssue
            var tmp_dir = new File(System.getProperty("java.io.tmpdir", "."));
            DUMP_DIR = new File(tmp_dir, "dexdump");
            assert DUMP_DIR.mkdirs();
        }
    }

    private static final Set<BaseDexClassLoader> loaders = new HashSet<>();
    private static final Set<Long> dumped = new HashSet<>();

    @DoNotShrink
    public static void add_loader(ClassLoader loader) {
        Log.w(TAG, "loader added: " + loader);
        loaders.add((BaseDexClassLoader) loader);
    }

    public static void dump() {
        Log.w(TAG, "dump start, package: " + ZygoteLoader.getPackageName());

        try {
            Files.copy(new File("/proc/self/maps").toPath(),
                    new File(Holder.DUMP_DIR, "maps.txt").toPath(),
                    StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        for (var loader : loaders) {
            var path_list = AccessI.INSTANCE.pathList(loader);
            if (path_list != null) {
                var elements = AccessI.INSTANCE.dexElements(path_list);
                if (elements != null) {
                    for (var element : elements) {
                        if (element != null) {
                            var dex = AccessI.INSTANCE.dexFile(element);
                            if (dex != null) {
                                long[] cookies = DexFileUtils.getCookie(dex);

                                final int first_dex = 1; // zero index is oat, not dex
                                for (int i = first_dex; i < cookies.length; i++) {
                                    long cookie = cookies[i];
                                    Log.w(TAG, "dump cookie: " + Long.toHexString(cookie));
                                    if (dumped.contains(cookie)) {
                                        Log.w(TAG, "skip, dumped already");
                                        continue;
                                    }
                                    dumped.add(cookie);

                                    byte[] data = DexFileDump.getDexFileContent(cookie);
                                    Log.w(TAG, "dump size: " + data.length);
                                    String name = String.format("classes%08X.dex", Arrays.hashCode(data));

                                    File f = new File(Holder.DUMP_DIR, name);
                                    Log.w(TAG, "dump file: " + f);
                                    if (f.isFile()) {
                                        Log.w(TAG, "skip, dumped already");
                                        continue;
                                    }
                                    try {
                                        assert f.createNewFile();
                                        Files.write(f.toPath(), data);
                                        Log.w(TAG, "dump writed");
                                    } catch (IOException e) {
                                        Log.w(TAG, "excepton", e);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        Log.w(TAG, "dump end, package: " + ZygoteLoader.getPackageName());
    }

    public static void start() {
        new Thread(() -> {
            while (true) {
                try {
                    //noinspection BusyWait
                    Thread.sleep(5000); // 5s
                } catch (InterruptedException e) { /* ignore */ }

                try {
                    dump();
                } catch (Throwable th) {
                    Log.e(TAG, "Exception", th);
                }
            }
        }).start();
    }
}

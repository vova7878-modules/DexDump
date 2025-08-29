package com.v7878.hooks.pmpatch;

import static com.v7878.hooks.pmpatch.Main.TAG;
import static com.v7878.unsafe.AndroidUnsafe.ARRAY_BYTE_BASE_OFFSET;
import static com.v7878.unsafe.Reflection.getHiddenMethods;
import static com.v7878.unsafe.access.AccessLinker.FieldAccessKind.INSTANCE_GETTER;

import android.util.Log;

import com.v7878.r8.annotations.DoNotOptimize;
import com.v7878.r8.annotations.DoNotShrink;
import com.v7878.r8.annotations.DoNotShrinkType;
import com.v7878.unsafe.ArtMethodUtils;
import com.v7878.unsafe.ClassUtils;
import com.v7878.unsafe.DexFileUtils;
import com.v7878.unsafe.ExtraMemoryAccess;
import com.v7878.unsafe.access.AccessLinker;
import com.v7878.unsafe.access.AccessLinker.FieldAccess;
import com.v7878.unsafe.foreign.LibDL;
import com.v7878.vmtools.DexFileDump;
import com.v7878.vmtools.MMap;
import com.v7878.zygisk.ZygoteLoader;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

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
            //noinspection ResultOfMethodCallIgnored
            DUMP_DIR.mkdirs();
        }
    }

    private static final Set<BaseDexClassLoader> loaders = ConcurrentHashMap.newKeySet();
    private static final Set<Long> dumped = new HashSet<>();

    @DoNotShrink
    public static void add_loader(ClassLoader loader) {
        Log.i(TAG, "loader added: " + loader);
        loaders.add((BaseDexClassLoader) loader);
    }

    public static void dump() {
        Log.i(TAG, "dump start, package: " + ZygoteLoader.getPackageName());

        try {
            Files.copy(new File("/proc/self/maps").toPath(),
                    new File(Holder.DUMP_DIR, "maps.txt").toPath(),
                    StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        var sb = new StringBuilder();

        var entry_points = new HashSet<Long>();

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
                                    Log.i(TAG, "dump cookie: " + Long.toHexString(cookie));

                                    for (var class_name : DexFileUtils.getClassNameList(cookie)) {
                                        try {
                                            var clazz = ClassUtils.forName(class_name, false, loader);
                                            var methods = getHiddenMethods(clazz);
                                            for (var method : methods) {
                                                if (Modifier.isNative(method.getModifiers())) {
                                                    var addr = ArtMethodUtils.getExecutableData(method);
                                                    var info = LibDL.dladdr(addr);
                                                    sb.append(String.format("%016X", info.fbase));
                                                    sb.append(" ");
                                                    sb.append(String.format("%016X", info.saddr));
                                                    sb.append(" ");
                                                    sb.append(String.format("%016X", addr));
                                                    sb.append(" ");
                                                    sb.append(info.fname);
                                                    sb.append(" ");
                                                    sb.append(info.sname);
                                                    sb.append(" ");
                                                    sb.append(method);
                                                    sb.append("\n");
                                                    if (info.fname == null) {
                                                        entry_points.add(addr);
                                                    }
                                                }
                                            }
                                        } catch (Throwable th) {
                                            Log.i(TAG, "skipped " + class_name);
                                        }
                                    }

                                    if (dumped.contains(cookie)) {
                                        Log.i(TAG, "skip, dumped already");
                                        continue;
                                    }
                                    dumped.add(cookie);

                                    byte[] data = DexFileDump.getDexFileContent(cookie);
                                    Log.i(TAG, "dump size: " + data.length);
                                    String dex_name = String.format("classes%08X.dex", Arrays.hashCode(data));

                                    File f = new File(Holder.DUMP_DIR, dex_name);
                                    Log.i(TAG, "dump file: " + f);
                                    try {
                                        if (f.createNewFile()) {
                                            Files.write(f.toPath(), data);
                                            Log.i(TAG, "dump writed");
                                        } else {
                                            Log.i(TAG, "skip, dumped already");
                                        }
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

        {
            File f = new File(Holder.DUMP_DIR, "methods.txt");
            try {
                Log.i(TAG, "methods file: " + f);
                //noinspection ReadWriteStringCanBeUsed
                Files.write(f.toPath(), sb.toString().getBytes(StandardCharsets.UTF_8));
                Log.i(TAG, "dump writed");
            } catch (IOException e) {
                Log.w(TAG, "excepton", e);
            }
        }

        try (var maps = MMap.maps("self")) {
            maps.forEach(entry -> {
                if (!entry.perms().contains("r")) {
                    return;
                }
                check_inside:
                {
                    for (var addr : entry_points) {
                        if (entry.start() <= addr && addr < entry.end()) {
                            break check_inside;
                        }
                    }
                    return;
                }

                long copy_begin = entry.start();
                long copy_end = entry.end();
                long copy_size = copy_end - copy_begin;

                var out = new byte[Math.toIntExact(copy_size)];

                ExtraMemoryAccess.copyMemory(null, copy_begin,
                        out, ARRAY_BYTE_BASE_OFFSET, copy_size);

                File f = new File(Holder.DUMP_DIR, String.format(
                        "%016X_%016X.bin", copy_begin, copy_end));
                try {
                    Log.i(TAG, "dump file: " + f);
                    Files.write(f.toPath(), out);
                    Log.i(TAG, "dump writed");
                } catch (IOException e) {
                    Log.w(TAG, "excepton", e);
                }
            });
        }

        Log.i(TAG, "dump end, package: " + ZygoteLoader.getPackageName());
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

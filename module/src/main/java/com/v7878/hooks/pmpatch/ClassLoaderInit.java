package com.v7878.hooks.pmpatch;

import static com.v7878.dex.DexConstants.ACC_PUBLIC;
import static com.v7878.hooks.pmpatch.Main.TAG;
import static com.v7878.unsafe.DexFileUtils.loadClass;
import static com.v7878.unsafe.DexFileUtils.openDexFile;
import static com.v7878.unsafe.DexFileUtils.setTrusted;
import static com.v7878.unsafe.Reflection.getDeclaredConstructors;

import android.util.Log;

import com.v7878.dex.DexIO;
import com.v7878.dex.builder.ClassBuilder;
import com.v7878.dex.immutable.ClassDef;
import com.v7878.dex.immutable.Dex;
import com.v7878.dex.immutable.TypeId;
import com.v7878.r8.annotations.DoNotOptimize;
import com.v7878.r8.annotations.DoNotShrink;
import com.v7878.unsafe.ClassUtils;
import com.v7878.unsafe.VM;
import com.v7878.vmtools.Hooks;

import java.util.List;

import dalvik.system.BaseDexClassLoader;
import dalvik.system.DexClassLoader;
import dalvik.system.DexFile;
import dalvik.system.InMemoryDexClassLoader;
import dalvik.system.PathClassLoader;

public class ClassLoaderInit {
    @DoNotShrink
    public static void init() {
        VM.setObjectClass(ClassLoaderInit.class.getClassLoader(), PathClassLoader.class);

        Log.w(TAG, "Deopt");

        for (var clazz : List.of(BaseDexClassLoader.class, PathClassLoader.class,
                InMemoryDexClassLoader.class, DexClassLoader.class)) {
            var constructors = getDeclaredConstructors(clazz);
            for (var constructor : constructors) {
                Hooks.deoptimize(constructor);
            }
        }

        Log.w(TAG, "Hook");

        @DoNotOptimize
        class Helper {
            public static Class<?> getClassLoaderHook() {
                return ClassLoaderHook.class;
            }
        }

        TypeId bdcl_id = TypeId.of(BaseDexClassLoader.class);
        ClassUtils.openClass(BaseDexClassLoader.class);

        String loader_base_name = "com.v7878.hooks.ClassLoaderBase";
        TypeId loader_base_id = TypeId.ofName(loader_base_name);

        ClassDef loader_base_def = ClassBuilder.build(loader_base_id, cb -> cb
                .withSuperClass(bdcl_id)
                .withFlags(ACC_PUBLIC)
        );

        DexFile dex = openDexFile(DexIO.write(Dex.of(loader_base_def)));
        setTrusted(dex);

        ClassLoader loader = Dumper.class.getClassLoader();
        loadClass(dex, loader_base_name, loader);

        VM.copyTables(Helper.getClassLoaderHook(), BaseDexClassLoader.class);
        VM.copyTables(Helper.getClassLoaderHook(), PathClassLoader.class);
        VM.copyTables(Helper.getClassLoaderHook(), InMemoryDexClassLoader.class);
        VM.copyTables(Helper.getClassLoaderHook(), DexClassLoader.class);

        Dumper.start();
    }
}

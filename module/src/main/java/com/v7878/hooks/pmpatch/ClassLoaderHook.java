package com.v7878.hooks.pmpatch;

import com.v7878.hooks.ClassLoaderBase;
import com.v7878.r8.annotations.DoNotObfuscate;
import com.v7878.r8.annotations.DoNotShrink;
import com.v7878.r8.annotations.DoNotShrinkType;

@DoNotShrinkType
public class ClassLoaderHook extends ClassLoaderBase {
    @DoNotShrink
    @DoNotObfuscate
    @Override
    public void reportClassLoaderChain() {
        Dumper.add_loader(this);
        super.reportClassLoaderChain();
    }
}

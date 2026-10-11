/*
 * This file is part of NativeCore, a library providing XposedAPI bindings to LSPlant
 * Copyright (c) 2021 Juby210 & Vendicated
 * Licensed under the Open Software License version 3.0
 */

#include <jni.h>
#include <string>
#include <lsplant.hpp>
#include <shadowhook.h>
#include <sys/mman.h>
#include <bits/sysconf.h>
#include "elf_img.h"
#include "log.h"
#include "profile_saver.h"
#include "hidden_api.h"
#include <sys/system_properties.h>
#include <cstdlib>
#include <cerrno>
#include "aliuhook.h"
#include "invoke_constructor.h"

int NativeCore::android_version = -1;
pine::ElfImg NativeCore::elf_img; // NOLINT(cert-err58-cpp)

void NativeCore::init(int version) {
    elf_img.Init("libart.so", version);
    android_version = version;
}

static size_t page_size_;

// Macros to align addresses to page boundaries
#define ALIGN_DOWN(addr, page_size)         ((addr) & -(page_size))
#define ALIGN_UP(addr, page_size)           (((addr) + ((page_size) - 1)) & ~((page_size) - 1))

static bool Unprotect(void *addr) {
    auto addr_uint = reinterpret_cast<uintptr_t>(addr);
    auto page_aligned_prt = reinterpret_cast<void *>(ALIGN_DOWN(addr_uint, page_size_));
    size_t size = page_size_;
    if (ALIGN_UP(addr_uint + page_size_, page_size_) != ALIGN_UP(addr_uint, page_size_)) {
        size += page_size_;
    }

    int result = mprotect(page_aligned_prt, size, PROT_READ | PROT_WRITE | PROT_EXEC);
    if (result == -1) {
        LOGE("mprotect failed for %p: %s (%d)", addr, strerror(errno), errno);
        return false;
    }
    return true;
}

// ShadowHook：shadowhook_unhook 直接接受 inline_hooker 返回的 stub（即 LSPlant 的 backup 指针），
// 与 LSPlant 的 inline_unhooker(func) 语义天然对齐，无需额外映射。
void *InlineHooker(void *address, void *replacement) {
    if (!Unprotect(address)) {
        return nullptr;
    }

    void *origin_call = nullptr;
    void *handle = shadowhook_hook_func_addr(address, replacement, &origin_call);
    if (handle == nullptr || origin_call == nullptr) {
        LOGE("shadowhook_hook_func_addr failed for %p (handle=%p, stub=%p)", address, handle, origin_call);
        if (handle != nullptr) shadowhook_unhook(origin_call);
        return nullptr;
    }
    return origin_call;
}

bool InlineUnhooker(void *func) {
    return shadowhook_unhook(func) == 0;
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_android_engine_HookEngine_isHooked0(JNIEnv *env, jclass, jobject method) {
    return lsplant::IsHooked(env, method);
}

extern "C"
JNIEXPORT jobject JNICALL
Java_com_android_engine_HookEngine_hook0(JNIEnv *env, jclass, jobject context,
                                               jobject original,
                                               jobject callback) {
    return lsplant::Hook(env, original, context, callback);
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_android_engine_HookEngine_unhook0(JNIEnv *env, jclass, jobject target) {
    return lsplant::UnHook(env, target);
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_android_engine_HookEngine_deoptimize0(JNIEnv *env, jclass, jobject method) {
    return lsplant::Deoptimize(env, method);
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_android_engine_HookEngine_makeClassInheritable0(JNIEnv *env, jclass, jclass clazz) {
    return lsplant::MakeClassInheritable(env, clazz);
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_android_engine_HookEngine_disableProfileSaver(JNIEnv *, jclass) {
    return disable_profile_saver();
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_android_engine_HookEngine_disableHiddenApiRestrictions(JNIEnv *env, jclass) {
    return disable_hidden_api(env);
}

extern "C"
JNIEXPORT jobject JNICALL
Java_com_android_engine_HookEngine_allocateInstance0(JNIEnv *env, jclass, jclass clazz) {
    return env->AllocObject(clazz);
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_com_android_engine_HookEngine_invokeConstructor0(JNIEnv *env, jclass, jobject instance, jobject constructor, jobjectArray args) {
    jmethodID constructorMethodId = env->FromReflectedMethod(constructor);
    if (!constructorMethodId) return JNI_FALSE;

    if (!args) {
        env->CallVoidMethod(instance, constructorMethodId);
        return JNI_TRUE;
    } else {
        return InvokeConstructorWithArgs(env, instance, constructor, args);
    }
}

JNIEXPORT jint JNICALL
JNI_OnLoad(JavaVM *vm, void *) {
    JNIEnv *env;
    if (vm->GetEnv((void **) &env, JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }

    page_size_ = static_cast<const size_t>(sysconf(_SC_PAGESIZE));

    {
        int api_level = android_get_device_api_level();

        if (api_level <= 0) {
            LOGE("Invalid SDK int %i", api_level);
            return JNI_ERR;
        }

        NativeCore::init(static_cast<int>(api_level));
    }

    // ShadowHook 初始化：SHARED 模式（默认模式，同地址可串链多个 hook）。
    // 宿主 app（如抖音 sysoptimizer/npth）会与引擎共用同一个 libshadowhook：
    // UNIQUE 模式会让宿主后续 hook 拿到 null backup → pc=0 崩溃。
    // debuggable=false：与注入场景一致。
    if (shadowhook_init(SHADOWHOOK_MODE_SHARED, false) != 0) {
        LOGE("shadowhook_init failed");
    } else {
        LOGI("shadowhook ready (mode=%d)", shadowhook_get_mode());
    }

    lsplant::InitInfo initInfo{
            .inline_hooker = InlineHooker,
            .inline_unhooker = InlineUnhooker,
            .art_symbol_resolver = [](std::string_view symbol) -> void * {
                return NativeCore::elf_img.GetSymbolAddress(symbol, false, false);
            },
            .art_symbol_prefix_resolver = [](std::string_view symbol) -> void * {
                return NativeCore::elf_img.GetSymbolAddress(symbol, false, true);
            },
            // 去特征双保险：即便 lsplant.hpp 默认值被上游改回，也强制运行时生成的
            // 类名/字段名/源名为中性，杜绝 "LSPHooker_"/"hooker"/"LSP" 指纹。
            .generated_class_name = "Q",
            .generated_source_name = "S",
            .generated_field_name = "f",
    };

    bool res = lsplant::Init(env, initInfo);
    if (!res) {
        LOGE("native init failed");
        return JNI_ERR;
    }

    LOGI("native init finished");

    res = LoadInvokeConstructorCache(env, NativeCore::android_version);
    if (!res) {
        LOGE("invoke_constructor init failed");
        return JNI_ERR;
    }

    return JNI_VERSION_1_6;
}

JNIEXPORT void JNICALL
JNI_OnUnload(JavaVM *vm, void *) {
    JNIEnv *env;
    vm->GetEnv((void **) &env, JNI_VERSION_1_1);

    UnloadInvokeConstructorCache(env);
}

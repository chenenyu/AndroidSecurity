#include <android/log.h>
#include <string>
#include "native-security.h"

#define LOGI(...) ((void)__android_log_print(ANDROID_LOG_INFO, "security", __VA_ARGS__))
#define LOGE(...) ((void)__android_log_print(ANDROID_LOG_ERROR, "security", __VA_ARGS__))

static int verifySign(JNIEnv *env);

jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    JNIEnv *env = NULL;
    if (vm->GetEnv((void **) &env, JNI_VERSION_1_4) != JNI_OK) {
        return JNI_ERR;
    }
    if (verifySign(env) == JNI_OK) {
        return JNI_VERSION_1_4;
    }
    LOGE("签名不一致!");
    return JNI_ERR;
}

static jobject getApplication(JNIEnv *env) {
    jobject application = NULL;
    jclass activity_thread_clz = env->FindClass("android/app/ActivityThread");
    if (activity_thread_clz != NULL) {
        jmethodID currentApplication = env->GetStaticMethodID(
                activity_thread_clz, "currentApplication", "()Landroid/app/Application;");
        if (currentApplication != NULL) {
            application = env->CallStaticObjectMethod(activity_thread_clz, currentApplication);
        } else {
            LOGE("Cannot find method: currentApplication() in ActivityThread.");
        }
        env->DeleteLocalRef(activity_thread_clz);
    } else {
        LOGE("Cannot find class: android.app.ActivityThread");
    }

    return application;
}

static const char *SIGN = "308203653082024da003020102020442e399f9300d06092a864886f70d01010"
        "b05003062310b3009060355040613023836310b300906035504081302434e3110300e060355040713"
        "074265696a696e67310f300d060355040a130662797465616d310f300d060355040b1306627974656"
        "16d31123010060355040313094368656e20456e79753020170d3137303331363033313034315a180f"
        "32313136303232313033313034315a3062310b3009060355040613023836310b30090603550408130"
        "2434e3110300e060355040713074265696a696e67310f300d060355040a130662797465616d310f30"
        "0d060355040b130662797465616d31123010060355040313094368656e20456e797530820122300d0"
        "6092a864886f70d01010105000382010f003082010a0282010100a82303afa4c0a66c381679f5e9be"
        "2f3f5142d82c47f2e40ef4bc23eaa511c48a01514a356679c9b0d5365f5c4d283abcb96e4a3afa2e3"
        "e612400aea74be35e0251a99ccc3ee0db4dcb4714dbc57466eb0dd097a07f05364f99eb81a8196562"
        "f88e95b48be19203f2acedda9dfc68150671c94957717d2c5de758fa3809d3de1c6f264d24ae336b9"
        "0a4fb873618fb3b9b4e53dced1b4f657ba85375f9f57a674cf327ecdc405ae4796fdae0100874ea5c"
        "226e8cf70150f19e40e61b9321cf4e407f5c9bd4410d5372dd21b759297b1d2e1bc3df624919ce5b0"
        "0c67512c5db0a480bfe0a6ad462f5c5f6cf4c45e3281988d8fdfd913d0c0e1ca4c702f2a8c191f902"
        "03010001a321301f301d0603551d0e04160414cf850a52b04103f63285964fd6dad179aabf9300300"
        "d06092a864886f70d01010b050003820101008c409146564b1a34ef49e61ecbc2da7db32d3b9e1c58"
        "15b1e2ba7eaba21dc0b5676aed0742450e3056489de4b6f3ad2b088f0038d32d3ed3ab7680de3fd7f"
        "d09abe4e426dbb0929e220a985356c38b6bb22b2f44dc9543391f0dbe49c5ec9c604de9a7de2e6ba0"
        "99c6cca0c5b098a069d53a55af0515cc0183bf81c733442dcff4fdea74f50e8870a1a579784dee29a"
        "97be59ab5098eaa73c5c4e43aa3b13f9382dbf6473b8fddb40958b2fe6696e8a5bc3ac53ec78f20b9"
        "bf212c6aeba3af4351771ca31bec26dc5424fc1cc7d129ba671165d0a600f0a2773708ef1596db795"
        "2e852dd1313f02baa97d92af073844ba1c57a2e3cadefdc841af7592462b65a";

static int verifySign(JNIEnv *env) {
    // Application object
    jobject application = getApplication(env);
    if (application == NULL) {
        return JNI_ERR;
    }
    // Context(ContextWrapper) class
    jclass context_clz = env->GetObjectClass(application);
    // getPackageManager()
    jmethodID getPackageManager = env->GetMethodID(context_clz, "getPackageManager",
                                                   "()Landroid/content/pm/PackageManager;");
    // android.content.pm.PackageManager object
    jobject package_manager = env->CallObjectMethod(application, getPackageManager);
    // PackageManager class
    jclass package_manager_clz = env->GetObjectClass(package_manager);
    // getPackageInfo()
    jmethodID getPackageInfo = env->GetMethodID(package_manager_clz, "getPackageInfo",
                                                "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");
    // context.getPackageName()
    jmethodID getPackageName = env->GetMethodID(context_clz, "getPackageName",
                                                "()Ljava/lang/String;");
    // call getPackageName() and cast from jobject to jstring
    jstring package_name = (jstring) (env->CallObjectMethod(application, getPackageName));
    // PackageInfo object
    jobject package_info = env->CallObjectMethod(package_manager, getPackageInfo, package_name, 64);
    // class PackageInfo
    jclass package_info_clz = env->GetObjectClass(package_info);
    // field signatures
    jfieldID signatures_field = env->GetFieldID(package_info_clz, "signatures",
                                                "[Landroid/content/pm/Signature;");
    jobject signatures = env->GetObjectField(package_info, signatures_field);
    jobjectArray signatures_array = (jobjectArray) signatures;
    jobject signature0 = env->GetObjectArrayElement(signatures_array, 0);
    jclass signature_clz = env->GetObjectClass(signature0);

    jmethodID toCharsString = env->GetMethodID(signature_clz, "toCharsString",
                                               "()Ljava/lang/String;");
    // call toCharsString()
    jstring signature_str = (jstring) (env->CallObjectMethod(signature0, toCharsString));

    // release
    env->DeleteLocalRef(application);
    env->DeleteLocalRef(context_clz);
    env->DeleteLocalRef(package_manager);
    env->DeleteLocalRef(package_manager_clz);
    env->DeleteLocalRef(package_name);
    env->DeleteLocalRef(package_info);
    env->DeleteLocalRef(package_info_clz);
    env->DeleteLocalRef(signatures);
    env->DeleteLocalRef(signature0);
    env->DeleteLocalRef(signature_clz);

    const char *sign = env->GetStringUTFChars(signature_str, NULL);
    if (sign == NULL) {
        LOGE("分配内存失败");
        return JNI_ERR;
    }

    LOGI("应用中读取到的签名为：%s", sign);
    LOGI("native中预置的签名为：%s", SIGN);
    int result = strcmp(sign, SIGN);
    // 使用之后要释放这段内存
    env->ReleaseStringUTFChars(signature_str, sign);
    env->DeleteLocalRef(signature_str);
    if (result == 0) { // 签名一致
        return JNI_OK;
    }

    return JNI_ERR;
}


jstring Java_com_chenenyu_security_Security_getSecret(JNIEnv *env, jclass type) {
    return env->NewStringUTF("Security str from native.");
}
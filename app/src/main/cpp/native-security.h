//
// Created by chenenyu on 2017/3/15.
//

#include <jni.h>

#ifndef ANDROIDSECURITY_NATIVE_SECURITY_H
#define ANDROIDSECURITY_NATIVE_SECURITY_H

#ifdef __cplusplus
extern "C" {
#endif

JNIEXPORT jstring JNICALL
Java_com_chenenyu_security_Security_getSecret(JNIEnv *env, jclass type);

#ifdef __cplusplus
}
#endif

#endif //ANDROIDSECURITY_NATIVE_SECURITY_H

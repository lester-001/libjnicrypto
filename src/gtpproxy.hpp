#ifndef _GTPPROXY_H_
#define _GTPPROXY_H_

#ifdef __cplusplus
extern "C" {
#endif


JNIEXPORT void JNICALL Java_com_ailink_jni_GtpProxy_Start(JNIEnv *env, jobject obj, jint jgnbid, jstring jlocalIp);
JNIEXPORT void JNICALL Java_com_ailink_jni_GtpProxy_Stop(JNIEnv *env, jobject obj, jint jgnbid);
JNIEXPORT void JNICALL Java_com_ailink_jni_GtpProxy_AddUeContext(JNIEnv *env, jobject obj, jint jgnbid, jint jueid, jlong dlAmbr, jlong ulAmbr);
JNIEXPORT void JNICALL Java_com_ailink_jni_GtpProxy_AddUeSession(JNIEnv *env, jobject obj, jint jgnbid, jint jueid,
    jint psi, jint qfi, jint local_teid, jint remote_teid, jstring jremoteip, jlong dlAmbr, jlong ulAmbr);

#ifdef __cplusplus
}
#endif

#endif
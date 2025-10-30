#ifndef _GTPPROXY_H_
#define _GTPPROXY_H_

#ifdef __cplusplus
extern "C" {
#endif

JNIEXPORT jint JNICALL Java_com_ailink_jni_GtpProxy_switchNamespace
  (JNIEnv *env, jobject obj, jstring nsPath);

JNIEXPORT void JNICALL Java_com_ailink_jni_GtpProxy_Start(JNIEnv *env, jobject obj, jint jgnbid, jstring jlocalIp);
JNIEXPORT void JNICALL Java_com_ailink_jni_GtpProxy_Stop(JNIEnv *env, jobject obj, jint jgnbid);
JNIEXPORT void JNICALL Java_com_ailink_jni_GtpProxy_AddUeContext(JNIEnv *env, jobject obj, jint jgnbid, jint jueid, jlong dlAmbr, jlong ulAmbr);
JNIEXPORT void JNICALL Java_com_ailink_jni_GtpProxy_AddUeSession(JNIEnv *env, jobject obj, jint jgnbid, jint jueid,
    jint psi, jint qfi, jint local_teid, jint remote_teid, jstring jremoteip, jlong dlAmbr, jlong ulAmbr);
JNIEXPORT void JNICALL Java_com_ailink_jni_GtpProxy_AddSipContext(JNIEnv *env, jobject obj, jint jgnbid, jint jueid, jint psi, jstring jueip, jstring jimsip);
    
JNIEXPORT void JNICALL Java_com_ailink_jni_GtpProxy_SendSipMsg(JNIEnv *env, jobject obj, jint jgnbid, jint jueid,
    jint psi, jint proto, jbyteArray jdata);
JNIEXPORT jbyteArray JNICALL Java_com_ailink_jni_GtpProxy_GetSipMsgWithTimeout(JNIEnv *env, jobject obj, jint jgnbid, jint jueid, jint timeout);


JNIEXPORT void JNICALL Java_com_ailink_jni_GtpProxy_SendUeData(JNIEnv *env, jobject obj, jint jgnbid, jint jueid,
    jint psi, jbyteArray jdata);
JNIEXPORT jbyteArray JNICALL Java_com_ailink_jni_GtpProxy_GetUeData(JNIEnv *env, jobject obj, jint jgnbid, jint jueid);
JNIEXPORT jbyteArray JNICALL Java_com_ailink_jni_GtpProxy_GetUeDataWithTimeout(JNIEnv *env, jobject obj, jint jgnbid, jint jueid, jint timeout);
#ifdef __cplusplus
}
#endif

#endif
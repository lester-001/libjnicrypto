#ifndef _CRYPTUTIL_H_
#define _CRYPTUTIL_H_

#ifdef __cplusplus
extern "C" {
#endif

JNIEXPORT void JNICALL Java_com_ailink_jni_CryptUtil_DeriveKeysSeafAmf(JNIEnv *env, jobject obj, jbyteArray jkAusf, jbyteArray jsupi, jbyteArray jsnn, jbyteArray jabba, jbyteArray jkseaf, jbyteArray jkamf);


JNIEXPORT void JNICALL Java_com_ailink_jni_CryptUtil_DeriveNasKeys(JNIEnv *env, jobject obj, jbyteArray jkamf, jbyteArray jkNasEnc, jbyteArray jkNasInt, jint ciphering, jint integrity);

JNIEXPORT void JNICALL Java_com_ailink_jni_CryptUtil_DeriveEpsNasKeys(JNIEnv *env, jobject obj, jbyteArray jkamf, jbyteArray jkNasEnc, jbyteArray jkNasInt, jint ciphering, jint integrity);

JNIEXPORT jint JNICALL Java_com_ailink_jni_CryptUtil_ComputeMacUia2(JNIEnv *env, jobject obj, jbyteArray jkey, jint jcount, jint jfresh, 
                jint jdir, jbyteArray jdata);

JNIEXPORT jint JNICALL Java_com_ailink_jni_CryptUtil_ComputeMacEia1(JNIEnv *env, jobject obj, jbyteArray jkey, jint jcount, jint jfresh, 
                jint jdir, jbyteArray jdata);

JNIEXPORT jint JNICALL Java_com_ailink_jni_CryptUtil_ComputeMacEia2(JNIEnv *env, jobject obj, jbyteArray jkey, jint jcount, jint jfresh, 
                jint jdir, jbyteArray jdata);

JNIEXPORT jint JNICALL Java_com_ailink_jni_CryptUtil_ComputeMacEia3(JNIEnv *env, jobject obj, jbyteArray jkey, jint jcount, jint jfresh, 
                jint jdir, jbyteArray jdata);

JNIEXPORT void JNICALL Java_com_ailink_jni_CryptUtil_EncryptEea1(JNIEnv *env, jobject obj, jbyteArray jkey, jint jcount, jint jfresh, 
                jint jdir, jbyteArray jdata);
JNIEXPORT void JNICALL Java_com_ailink_jni_CryptUtil_DecryptEea1(JNIEnv *env, jobject obj, jbyteArray jkey, jint jcount, jint jfresh, 
                jint jdir, jbyteArray jdata); 

JNIEXPORT void JNICALL Java_com_ailink_jni_CryptUtil_EncryptEea2(JNIEnv *env, jobject obj, jbyteArray jkey, jint jcount, jint jfresh, 
                jint jdir, jbyteArray jdata);
JNIEXPORT void JNICALL Java_com_ailink_jni_CryptUtil_DecryptEea2(JNIEnv *env, jobject obj, jbyteArray jkey, jint jcount, jint jfresh, 
                jint jdir, jbyteArray jdata);
                
JNIEXPORT void JNICALL Java_com_ailink_jni_CryptUtil_EncryptEea3(JNIEnv *env, jobject obj, jbyteArray jkey, jint jcount, jint jfresh, 
                jint jdir, jbyteArray jdata);
JNIEXPORT void JNICALL Java_com_ailink_jni_CryptUtil_DecryptEea3(JNIEnv *env, jobject obj, jbyteArray jkey, jint jcount, jint jfresh, 
                jint jdir, jbyteArray jdata);

JNIEXPORT int JNICALL Java_com_ailink_jni_CryptUtil_Handle4gAuthentication(JNIEnv *env, jobject obj, 
        jint op_type, jbyteArray jopc, jbyteArray jkey, 
        jbyteArray jrand, jbyteArray jautn, jbyteArray jplmn, 
        jbyteArray jkasme, jbyteArray jres);
JNIEXPORT int JNICALL Java_com_ailink_jni_CryptUtil_Handle5gAuthentication(JNIEnv *env, jobject obj, 
        jint op_type, jbyteArray jopc, jbyteArray jkey, jbyteArray jsupi, 
        jbyteArray jrand, jbyteArray jautn, jbyteArray jsnn, jbyteArray jabba, 
        jbyteArray jkseaf, jbyteArray jkamf, jbyteArray jres);
#ifdef __cplusplus
}
#endif

#endif
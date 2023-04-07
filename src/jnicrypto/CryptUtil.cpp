#include <jni.h>
#include "CryptUtil.hpp"
#include <lib/crypt/crypt.hpp>

using namespace crypto;

JNIEXPORT void JNICALL Java_com_ailink_jni_CryptUtil_DeriveKeysSeafAmf(JNIEnv *env, jobject obj, jbyteArray jkAusf, jbyteArray jsupi, jbyteArray jsnn, jbyteArray jabba, jbyteArray jkseaf, jbyteArray jkamf) {
    
        void *supi = (void*)env->GetByteArrayElements(jsupi,NULL);
        void *snn = (void*)env->GetByteArrayElements(jsnn,NULL);
        void *abba = (void*)env->GetByteArrayElements(jabba,NULL);
        void *kAusf = (void*)env->GetByteArrayElements(jkAusf,NULL);

        uint32_t supi_len = env->GetArrayLength(jsupi);
        uint32_t abba_len = env->GetArrayLength(jabba);
        uint32_t kAusf_len = env->GetArrayLength(jkAusf);
        uint32_t snn_len = env->GetArrayLength(jsnn);

        uint32_t kseaf[32];
        uint32_t kamf[32];

        DeriveKeysSeafAmf_c((const char *)kAusf, kAusf_len, (const char *)supi, (const char *)snn, snn_len, (char *)abba, abba_len, (char *)kseaf, (char *)kamf);

	env->SetByteArrayRegion(jkseaf, 0, 32, (jbyte*)kseaf);
	env->SetByteArrayRegion(jkamf, 0, 32, (jbyte*)kamf);

        env->ReleaseByteArrayElements(jsupi, (jbyte*)supi,JNI_ABORT);
        env->ReleaseByteArrayElements(jsnn, (jbyte*)snn,JNI_ABORT);
        env->ReleaseByteArrayElements(jabba, (jbyte*)abba,JNI_ABORT);
}

JNIEXPORT void JNICALL Java_com_ailink_jni_CryptUtil_DeriveNasKeys(JNIEnv *env, jobject obj, jbyteArray jkamf, jbyteArray jkNasEnc, jbyteArray jkNasInt, jint ciphering, jint integrity) {

        void *kamf = (void*)env->GetByteArrayElements(jkamf,NULL);

        uint32_t kamf_len = env->GetArrayLength(jkamf);

        uint8_t kNasEnc[16];
        uint8_t kNasInt[16];

        DeriveNasKeysC((uint32_t)ciphering, (uint32_t)integrity, (const char *)kamf, (uint32_t)kamf_len, kNasEnc, kNasInt);
        
	env->SetByteArrayRegion(jkNasEnc, 0, 16, (jbyte*)kNasEnc);
	env->SetByteArrayRegion(jkNasInt, 0, 16, (jbyte*)kNasInt);

        env->ReleaseByteArrayElements(jkamf, (jbyte*)kamf,JNI_ABORT);
}

JNIEXPORT jint JNICALL Java_com_ailink_jni_CryptUtil_ComputeMacUia2(JNIEnv *env, jobject obj, jbyteArray jkey, jint jcount, jint jfresh, 
                jint jdir, jbyteArray jdata) {
        void *key = (void*)env->GetByteArrayElements(jkey,NULL);
        uint32_t key_len = env->GetArrayLength(jkey);
        int ret;

        void *data = (void*)env->GetByteArrayElements(jkey,NULL);
        uint32_t data_len = env->GetArrayLength(jkey);

        ret = ComputeMacUia2_c((signed char*)key, key_len, (uint32_t)jcount, (uint32_t)jfresh, (uint32_t)jdir, (signed char*)data, data_len);

        env->ReleaseByteArrayElements(jdata, (jbyte*)data,JNI_ABORT);
        env->ReleaseByteArrayElements(jkey, (jbyte*)key,JNI_ABORT);
        return (jint)ret;
}

JNIEXPORT jint JNICALL Java_com_ailink_jni_CryptUtil_ComputeMacEia1(JNIEnv *env, jobject obj, jbyteArray jkey, jint jcount, jint jfresh, 
                jint jdir, jbyteArray jdata) {
        void *key = (void*)env->GetByteArrayElements(jkey,NULL);
        uint32_t key_len = env->GetArrayLength(jkey);
        int ret = 0;

        void *data = (void*)env->GetByteArrayElements(jkey,NULL);
        uint32_t data_len = env->GetArrayLength(jkey);

        ret = ComputeMacEia1_c((signed char*)key, key_len, (uint32_t)jcount, (uint32_t)jfresh, (uint32_t)jdir, (signed char*)data, data_len);

        uint32_t fresh = jfresh << 27;
        ret = ComputeMacUia2((const uint8_t *)key, (uint32_t)jcount, fresh, (uint32_t)jdir, (uint8_t *)data, data_len);
        env->ReleaseByteArrayElements(jdata, (jbyte*)data,JNI_ABORT);
        env->ReleaseByteArrayElements(jkey, (jbyte*)key,JNI_ABORT);
        return (jint)ret;
}


JNIEXPORT jint JNICALL Java_com_ailink_jni_CryptUtil_ComputeMacEia2(JNIEnv *env, jobject obj, jbyteArray jkey, jint jcount, jint jfresh, 
                jint jdir, jbyteArray jdata) {
        void *key = (void*)env->GetByteArrayElements(jkey,NULL);
        uint32_t key_len = env->GetArrayLength(jkey);
        int ret;

        void *data = (void*)env->GetByteArrayElements(jdata,NULL);
        uint32_t data_len = env->GetArrayLength(jdata);

        ret = ComputeMacEia2_c((signed char*)key, key_len, (uint32_t)jcount, (uint32_t)jfresh, (uint32_t)jdir, (signed char*)data, data_len);

        env->ReleaseByteArrayElements(jdata, (jbyte*)data,JNI_ABORT);
        env->ReleaseByteArrayElements(jkey, (jbyte*)key,JNI_ABORT);
        return (jint)ret;
}

JNIEXPORT jint JNICALL Java_com_ailink_jni_CryptUtil_ComputeMacEia3(JNIEnv *env, jobject obj, jbyteArray jkey, jint jcount, jint jfresh, 
                jint jdir, jbyteArray jdata) {
        void *key = (void*)env->GetByteArrayElements(jkey,NULL);
        uint32_t key_len = env->GetArrayLength(jkey);
        int ret;

        void *data = (void*)env->GetByteArrayElements(jkey,NULL);
        uint32_t data_len = env->GetArrayLength(jkey);

        ret = ComputeMacEia3_c((signed char*)key, key_len, (uint32_t)jcount, (uint32_t)jfresh, (uint32_t)jdir, (signed char*)data, data_len);

        env->ReleaseByteArrayElements(jdata, (jbyte*)data,JNI_ABORT);
        env->ReleaseByteArrayElements(jkey, (jbyte*)key,JNI_ABORT);
        return (jint)ret;
}

JNIEXPORT void JNICALL Java_com_ailink_jni_CryptUtil_EncryptEea1(JNIEnv *env, jobject obj, jbyteArray jkey, jint jcount, jint jfresh, 
                jint jdir, jbyteArray jdata) {
        void *key = (void*)env->GetByteArrayElements(jkey,NULL);
        uint32_t key_len = env->GetArrayLength(jkey);

        void *data = (void*)env->GetByteArrayElements(jkey,NULL);
        uint32_t data_len = env->GetArrayLength(jkey);

        EncryptEea1_c((signed char*)key, key_len, (uint32_t)jcount, (uint32_t)jfresh, (uint32_t)jdir, (signed char*)data, data_len);

        env->ReleaseByteArrayElements(jdata, (jbyte*)data,JNI_ABORT);
        env->ReleaseByteArrayElements(jkey, (jbyte*)key,JNI_ABORT);
}


JNIEXPORT void JNICALL Java_com_ailink_jni_CryptUtil_DecryptEea1(JNIEnv *env, jobject obj, jbyteArray jkey, jint jcount, jint jfresh, 
                jint jdir, jbyteArray jdata) {
        void *key = (void*)env->GetByteArrayElements(jkey,NULL);
        uint32_t key_len = env->GetArrayLength(jkey);

        void *data = (void*)env->GetByteArrayElements(jkey,NULL);
        uint32_t data_len = env->GetArrayLength(jkey);

        DecryptEea1_c((signed char*)key, key_len, (uint32_t)jcount, (uint32_t)jfresh, (uint32_t)jdir, (signed char*)data, data_len);

        env->ReleaseByteArrayElements(jdata, (jbyte*)data,JNI_ABORT);
        env->ReleaseByteArrayElements(jkey, (jbyte*)key,JNI_ABORT);
}

JNIEXPORT void JNICALL Java_com_ailink_jni_CryptUtil_EncryptEea2(JNIEnv *env, jobject obj, jbyteArray jkey, jint jcount, jint jfresh, 
                jint jdir, jbyteArray jdata) {
        void *key = (void*)env->GetByteArrayElements(jkey,NULL);
        uint32_t key_len = env->GetArrayLength(jkey);

        void *data = (void*)env->GetByteArrayElements(jkey,NULL);
        uint32_t data_len = env->GetArrayLength(jkey);

        EncryptEea2_c((signed char*)key, key_len, (uint32_t)jcount, (uint32_t)jfresh, (uint32_t)jdir, (signed char*)data, data_len);

        env->ReleaseByteArrayElements(jdata, (jbyte*)data,JNI_ABORT);
        env->ReleaseByteArrayElements(jkey, (jbyte*)key,JNI_ABORT);
}

JNIEXPORT void JNICALL Java_com_ailink_jni_CryptUtil_DecryptEea2(JNIEnv *env, jobject obj, jbyteArray jkey, jint jcount, jint jfresh, 
                jint jdir, jbyteArray jdata) {
        void *key = (void*)env->GetByteArrayElements(jkey,NULL);
        uint32_t key_len = env->GetArrayLength(jkey);

        void *data = (void*)env->GetByteArrayElements(jkey,NULL);
        uint32_t data_len = env->GetArrayLength(jkey);

        DecryptEea2_c((signed char*)key, key_len, (uint32_t)jcount, (uint32_t)jfresh, (uint32_t)jdir, (signed char*)data, data_len);

        env->ReleaseByteArrayElements(jdata, (jbyte*)data,JNI_ABORT);
        env->ReleaseByteArrayElements(jkey, (jbyte*)key,JNI_ABORT);
}

JNIEXPORT void JNICALL Java_com_ailink_jni_CryptUtil_EncryptEea3(JNIEnv *env, jobject obj, jbyteArray jkey, jint jcount, jint jfresh, 
                jint jdir, jbyteArray jdata) {
        void *key = (void*)env->GetByteArrayElements(jkey,NULL);
        uint32_t key_len = env->GetArrayLength(jkey);

        void *data = (void*)env->GetByteArrayElements(jkey,NULL);
        uint32_t data_len = env->GetArrayLength(jkey);

        EncryptEea3_c((signed char*)key, key_len, (uint32_t)jcount, (uint32_t)jfresh, (uint32_t)jdir, (signed char*)data, data_len);

        env->ReleaseByteArrayElements(jdata, (jbyte*)data,JNI_ABORT);
        env->ReleaseByteArrayElements(jkey, (jbyte*)key,JNI_ABORT);
}

JNIEXPORT void JNICALL Java_com_ailink_jni_CryptUtil_DecryptEea3(JNIEnv *env, jobject obj, jbyteArray jkey, jint jcount, jint jfresh, 
                jint jdir, jbyteArray jdata) {
        void *key = (void*)env->GetByteArrayElements(jkey,NULL);
        uint32_t key_len = env->GetArrayLength(jkey);

        void *data = (void*)env->GetByteArrayElements(jkey,NULL);
        uint32_t data_len = env->GetArrayLength(jkey);

        DecryptEea3_c((signed char*)key, key_len, (uint32_t)jcount, (uint32_t)jfresh, (uint32_t)jdir, (signed char*)data, data_len);

        env->ReleaseByteArrayElements(jdata, (jbyte*)data,JNI_ABORT);
        env->ReleaseByteArrayElements(jkey, (jbyte*)key,JNI_ABORT);
}
#include <jni.h>
#include "CryptUtil.hpp"
#include <lib/crypt/eea2.hpp>
#include <lib/crypt/eea3.hpp>
#include <lib/crypt/eia2.hpp>
#include <lib/crypt/crypt.hpp>
#include <cstring>

using namespace crypto;

void DeriveNasKeys(uint32_t ciphering, uint32_t integrity, const char *k_amf, uint32_t kamf_len, uint8_t *kNasEnc, uint8_t *kNasInt)
{   
    const int N_NAS_enc_alg = 0x01;
    const int N_NAS_int_alg = 0x02;
    OctetString s1[2];
    s1[0] = OctetString::FromOctet(N_NAS_enc_alg);
    s1[1] = OctetString::FromOctet((int)ciphering);

    OctetString s2[2];
    s2[0] = OctetString::FromOctet(N_NAS_int_alg);
    s2[1] = OctetString::FromOctet((int)integrity);

    OctetString o_kamf = OctetString::FromArray((const uint8_t *)k_amf, kamf_len);
    auto kdfEnc = crypto::CalculateKdfKey(o_kamf, 0x69, s1, 2);
    auto kdfInt = crypto::CalculateKdfKey(o_kamf, 0x69, s2, 2);

    OctetString keys_kNasEnc = kdfEnc.subCopy(16, 16);
    OctetString keys_kNasInt = kdfInt.subCopy(16, 16); 
    std::memcpy(kNasEnc, keys_kNasEnc.data(), keys_kNasEnc.length());
    std::memcpy(kNasInt, keys_kNasInt.data(), keys_kNasInt.length());
}

void DeriveKeysSeafAmf(const char *kausf, int ausf_len, const char *supi, const char *snn, uint32_t snn_len, const char *abba, uint32_t abba_len, char *k_seaf, char *k_amf)
{
    OctetString kSeaf{};
    OctetString kAmf{};
    std::string s_snn;
    std::string s_supi(supi);
    std::string s_abba(abba) ;

    s_snn.assign(snn, snn_len);

    OctetString kAusf = OctetString::FromArray((const uint8_t *)kausf, ausf_len);
    OctetString s1[1];
    s1[0] = crypto::EncodeKdfString(s_snn);

    OctetString s2[2];
    s2[0] = crypto::EncodeKdfString(s_supi);

    for (uint32_t i = 0; i < abba_len; i ++)
    {
        s2[1].appendOctet(abba[i]);
    }

    kSeaf = crypto::CalculateKdfKey(kAusf, 0x6C, s1, 1);
    kAmf = crypto::CalculateKdfKey(kSeaf, 0x6D, s2, 2);

    memcpy(k_seaf, kSeaf.data(), kSeaf.length());
    memcpy(k_amf, kAmf.data(), kAmf.length());
}

uint32_t ComputeMacEia2(signed char *pKey, uint32_t key_len, uint32_t count, int bearer, int direction, signed char *pData, uint32_t length)
{
    OctetString key = OctetString{std::vector<uint8_t>{pKey, pKey+key_len }};
    OctetString message = OctetString{std::vector<uint8_t>{pData, pData+length }};
    return eia2::Compute(count, bearer, direction, message, key);
}

void DecryptEea1(signed char *pKey, uint32_t key_len, uint32_t count, uint32_t bearer, uint32_t dir, signed char * pData, uint32_t length)
{
    EncryptUea2((const uint8_t *)pKey, count, bearer, dir, (uint8_t *)pData, length);
}

uint32_t ComputeMacEia3(signed char *pKey, uint32_t key_len, uint32_t count, int bearer, int direction, signed char * pData, uint32_t length)
{
    return eea3::EIA3((const uint8_t *)pKey, count, direction, bearer, length * 8,
                      reinterpret_cast<const uint32_t *>(pData));
}

void EncryptEea2(signed char *pKey, uint32_t key_len, uint32_t count, int bearer, int direction, signed char * pData, uint32_t length)
{
    OctetString key = OctetString::FromArray((const uint8_t *)pKey, key_len);
    OctetString message= OctetString::FromArray((const uint8_t *)pData, length);

    eea2::Encrypt(count, bearer, direction, message, key);
}

void DecryptEea2(signed char *pKey, uint32_t key_len, uint32_t count, int bearer, int direction, signed char * pData, uint32_t length)
{
    OctetString key = OctetString::FromArray((const uint8_t *)pKey, key_len);
    OctetString message= OctetString::FromArray((const uint8_t *)pData, length);
    
    eea2::Decrypt(count, bearer, direction, message, key);
}

void EncryptEea3(signed char *pKey,uint32_t count, int bearer, int direction, signed char * pData, uint32_t length)
{
    eea3::EEA3((const uint8_t *)pKey, count, bearer, direction, length * 8,
               reinterpret_cast<uint32_t *>(pData));
}

void DecryptEea3(signed char *pKey, uint32_t count, int bearer, int direction, signed char * pData, uint32_t length)
{
    eea3::EEA3((const uint8_t *)pKey, count, bearer, direction, length * 8,
               reinterpret_cast<uint32_t *>(pData));
}

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

        DeriveKeysSeafAmf((const char *)kAusf, kAusf_len, (const char *)supi, (const char *)snn, snn_len, (char *)abba, abba_len, (char *)kseaf, (char *)kamf);

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

        DeriveNasKeys((uint32_t)ciphering, (uint32_t)integrity, (const char *)kamf, (uint32_t)kamf_len, (uint8_t *)kNasEnc, (uint8_t *)kNasInt);
        
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

        ret = ComputeMacUia2((const uint8_t *)key, (uint32_t)jcount, (uint32_t)jfresh, (uint32_t)jdir, (const uint8_t *)data, data_len);

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

        ret = ComputeMacEia2((signed char*)key, key_len, (uint32_t)jcount, (uint32_t)jfresh, (uint32_t)jdir, (signed char*)data, data_len);

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

        ret = ComputeMacEia3((signed char*)key, key_len, (uint32_t)jcount, (uint32_t)jfresh, (uint32_t)jdir, (signed char*)data, data_len);

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

        EncryptUea2((uint8_t *)key, (uint32_t)jcount, (uint32_t)jfresh, (uint32_t)jdir, (uint8_t*)data, data_len);

        env->ReleaseByteArrayElements(jdata, (jbyte*)data,JNI_ABORT);
        env->ReleaseByteArrayElements(jkey, (jbyte*)key,JNI_ABORT);
}

JNIEXPORT void JNICALL Java_com_ailink_jni_CryptUtil_DecryptEea1(JNIEnv *env, jobject obj, jbyteArray jkey, jint jcount, jint jfresh, 
                jint jdir, jbyteArray jdata) {
        void *key = (void*)env->GetByteArrayElements(jkey,NULL);
        uint32_t key_len = env->GetArrayLength(jkey);

        void *data = (void*)env->GetByteArrayElements(jkey,NULL);
        uint32_t data_len = env->GetArrayLength(jkey);

        DecryptEea1((signed char*)key, key_len, (uint32_t)jcount, (uint32_t)jfresh, (uint32_t)jdir, (signed char*)data, data_len);

        env->ReleaseByteArrayElements(jdata, (jbyte*)data,JNI_ABORT);
        env->ReleaseByteArrayElements(jkey, (jbyte*)key,JNI_ABORT);
}

JNIEXPORT void JNICALL Java_com_ailink_jni_CryptUtil_EncryptEea2(JNIEnv *env, jobject obj, jbyteArray jkey, jint jcount, jint jfresh, 
                jint jdir, jbyteArray jdata) {
        void *key = (void*)env->GetByteArrayElements(jkey,NULL);
        uint32_t key_len = env->GetArrayLength(jkey);

        void *data = (void*)env->GetByteArrayElements(jkey,NULL);
        uint32_t data_len = env->GetArrayLength(jkey);

        EncryptEea2((signed char*)key, key_len, (uint32_t)jcount, (uint32_t)jfresh, (uint32_t)jdir, (signed char*)data, data_len);

        env->ReleaseByteArrayElements(jdata, (jbyte*)data,JNI_ABORT);
        env->ReleaseByteArrayElements(jkey, (jbyte*)key,JNI_ABORT);
}

JNIEXPORT void JNICALL Java_com_ailink_jni_CryptUtil_DecryptEea2(JNIEnv *env, jobject obj, jbyteArray jkey, jint jcount, jint jfresh, 
                jint jdir, jbyteArray jdata) {
        void *key = (void*)env->GetByteArrayElements(jkey,NULL);
        uint32_t key_len = env->GetArrayLength(jkey);

        void *data = (void*)env->GetByteArrayElements(jkey,NULL);
        uint32_t data_len = env->GetArrayLength(jkey);

        DecryptEea2((signed char*)key, key_len, (uint32_t)jcount, (uint32_t)jfresh, (uint32_t)jdir, (signed char*)data, data_len);

        env->ReleaseByteArrayElements(jdata, (jbyte*)data,JNI_ABORT);
        env->ReleaseByteArrayElements(jkey, (jbyte*)key,JNI_ABORT);
}

JNIEXPORT void JNICALL Java_com_ailink_jni_CryptUtil_EncryptEea3(JNIEnv *env, jobject obj, jbyteArray jkey, jint jcount, jint jfresh, 
                jint jdir, jbyteArray jdata) {
        void *key = (void*)env->GetByteArrayElements(jkey,NULL);
        uint32_t key_len = env->GetArrayLength(jkey);

        void *data = (void*)env->GetByteArrayElements(jkey,NULL);
        uint32_t data_len = env->GetArrayLength(jkey);

        EncryptEea3((signed char*)key, (uint32_t)jcount, (uint32_t)jfresh, (uint32_t)jdir, (signed char*)data, data_len);

        env->ReleaseByteArrayElements(jdata, (jbyte*)data,JNI_ABORT);
        env->ReleaseByteArrayElements(jkey, (jbyte*)key,JNI_ABORT);
}

JNIEXPORT void JNICALL Java_com_ailink_jni_CryptUtil_DecryptEea3(JNIEnv *env, jobject obj, jbyteArray jkey, jint jcount, jint jfresh, 
                jint jdir, jbyteArray jdata) {
        void *key = (void*)env->GetByteArrayElements(jkey,NULL);
        uint32_t key_len = env->GetArrayLength(jkey);

        void *data = (void*)env->GetByteArrayElements(jkey,NULL);
        uint32_t data_len = env->GetArrayLength(jkey);

        DecryptEea3((signed char*)key, (uint32_t)jcount, (uint32_t)jfresh, (uint32_t)jdir, (signed char*)data, data_len);

        env->ReleaseByteArrayElements(jdata, (jbyte*)data,JNI_ABORT);
        env->ReleaseByteArrayElements(jkey, (jbyte*)key,JNI_ABORT);
}
#include <jni.h>
#include "CryptUtil.hpp"
#include <lib/crypt/eea2.hpp>
#include <lib/crypt/eea3.hpp>
#include <lib/crypt/eia2.hpp>
#include <lib/crypt/crypt.hpp>
#include <lib/crypt/milenage.hpp>
#include <utils/octet_string.hpp>
#include <utils/sqn_mng.hpp>
#include <cstring>

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

        DeriveKeysSeafAmf((const char *)kAusf, kAusf_len, (const char *)supi, supi_len, (const char *)snn, snn_len, (char *)abba, abba_len, (char *)kseaf, (char *)kamf);

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

JNIEXPORT void JNICALL Java_com_ailink_jni_CryptUtil_DeriveEpsNasKeys(JNIEnv *env, jobject obj, jbyteArray jkamf, jbyteArray jkNasEnc, jbyteArray jkNasInt, jint ciphering, jint integrity) {

        void *kamf = (void*)env->GetByteArrayElements(jkamf,NULL);

        uint32_t kamf_len = env->GetArrayLength(jkamf);

        uint8_t kNasEnc[16];
        uint8_t kNasInt[16];

        DeriveEpsNasKeysC((uint32_t)ciphering, (uint32_t)integrity, (const char *)kamf, (uint32_t)kamf_len, kNasEnc, kNasInt);
        
	env->SetByteArrayRegion(jkNasEnc, 0, 16, (jbyte*)kNasEnc);
	env->SetByteArrayRegion(jkNasInt, 0, 16, (jbyte*)kNasInt);

        env->ReleaseByteArrayElements(jkamf, (jbyte*)kamf,JNI_ABORT);
}

JNIEXPORT jint JNICALL Java_com_ailink_jni_CryptUtil_ComputeMacUia2(JNIEnv *env, jobject obj, jbyteArray jkey, jint jcount, jint jfresh, 
                jint jdir, jbyteArray jdata) {
        void *key = (void*)env->GetByteArrayElements(jkey,NULL);
//        uint32_t key_len = env->GetArrayLength(jkey);
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
//        uint32_t key_len = env->GetArrayLength(jkey);

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
//        uint32_t key_len = env->GetArrayLength(jkey);

        void *data = (void*)env->GetByteArrayElements(jkey,NULL);
        uint32_t data_len = env->GetArrayLength(jkey);

        EncryptEea3((signed char*)key, (uint32_t)jcount, (uint32_t)jfresh, (uint32_t)jdir, (signed char*)data, data_len);

        env->ReleaseByteArrayElements(jdata, (jbyte*)data,JNI_ABORT);
        env->ReleaseByteArrayElements(jkey, (jbyte*)key,JNI_ABORT);
}

JNIEXPORT void JNICALL Java_com_ailink_jni_CryptUtil_DecryptEea3(JNIEnv *env, jobject obj, jbyteArray jkey, jint jcount, jint jfresh, 
                jint jdir, jbyteArray jdata) {
        void *key = (void*)env->GetByteArrayElements(jkey,NULL);
//        uint32_t key_len = env->GetArrayLength(jkey);

        void *data = (void*)env->GetByteArrayElements(jkey,NULL);
        uint32_t data_len = env->GetArrayLength(jkey);

        DecryptEea3((signed char*)key, (uint32_t)jcount, (uint32_t)jfresh, (uint32_t)jdir, (signed char*)data, data_len);

        env->ReleaseByteArrayElements(jdata, (jbyte*)data,JNI_ABORT);
        env->ReleaseByteArrayElements(jkey, (jbyte*)key,JNI_ABORT);
}
crypto::milenage::Milenage calculateMilenage(int op_type, const OctetString &opc, const OctetString &key, 
        const OctetString &sqn, const OctetString &rand, OctetString &amf)
{
    if (op_type == 1)
        return crypto::milenage::Calculate(opc, key, rand, sqn, amf);

    OctetString opc_new = crypto::milenage::CalculateOpC(opc, key);
    return crypto::milenage::Calculate(opc_new, key, rand, sqn, amf);
}

int validateAutn(SqnManager *sqnMng, int op_type, const OctetString &opc, 
        const OctetString &key, const OctetString &rand, const OctetString &autn)
{
    // Decode AUTN
    OctetString receivedSQNxorAK = autn.subCopy(0, 6);
    OctetString receivedAMF = autn.subCopy(6, 2);
    OctetString receivedMAC = autn.subCopy(8, 8);

    // Check the separation bit
    if (receivedAMF.get(0).bit(7) != 1)
    {
        printf("AUTN validation SEP-BIT failure. expected: 1, received: 0");
        return 2;
    }

    auto sqn = sqnMng->getSqn();
    auto milenage = calculateMilenage(op_type, opc, key, sqn, rand, receivedAMF);
    OctetString receivedSQN = OctetString::Xor(receivedSQNxorAK, milenage.ak);

    if (!sqnMng->checkSqn(receivedSQN))
        return 3;

    // Re-execute the milenage calculation (if case of sqn is changed with the received value)
    milenage = calculateMilenage(op_type, opc, key, sqnMng->getSqn(), rand, receivedAMF);

    if (receivedMAC != milenage.mac_a)
    {
        printf("AUTN validation MAC mismatch. expected [%s] received [%s]", milenage.mac_a.toHexString().c_str(),
                      receivedMAC.toHexString().c_str());
        return 1;
    }

    return 0;
}

int handle4gAuthentication(int op_type, const OctetString &opc, const OctetString &key, 
        const OctetString &rand, const OctetString &autn, const OctetString &plmn, 
        OctetString &res, OctetString &kasme)
{
    SqnManager sqnMng(5ull, 1ull << 28ull);

    OctetString receivedSQNxorAK = autn.subCopy(0, 6);
    OctetString receivedAMF = autn.subCopy(6, 2);
    OctetString receivedMAC = autn.subCopy(8, 8);

    int autnCheck = validateAutn(&sqnMng, op_type, opc, key, rand, autn);

    if (autnCheck == 0)
    {
        // Calculate milenage
        auto milenage = calculateMilenage(op_type, opc, key, sqnMng.getSqn(), rand, receivedAMF);
        auto ckIk = OctetString::Concat(milenage.ck, milenage.ik);
        auto sqnXorAk = OctetString::Xor(sqnMng.getSqn(), milenage.ak);
        res = milenage.res.copy();
        kasme = CalculateKAusfFor4gAka(milenage.ck, milenage.ik, plmn, sqnXorAk);
    }

    return autnCheck;
}

JNIEXPORT int JNICALL Java_com_ailink_jni_CryptUtil_Handle4gAuthentication(JNIEnv *env, jobject obj, 
        jint op_type, jbyteArray jopc, jbyteArray jkey, 
        jbyteArray jrand, jbyteArray jautn, jbyteArray jplmn, 
        jbyteArray jkasme, jbyteArray jres) {
        void *opc = (void*)env->GetByteArrayElements(jopc,NULL);
        uint32_t opc_len = env->GetArrayLength(jopc);
        void *key = (void*)env->GetByteArrayElements(jkey,NULL);
        uint32_t key_len = env->GetArrayLength(jkey);
        void *rand = (void*)env->GetByteArrayElements(jrand,NULL);
        uint32_t rand_len = env->GetArrayLength(jrand);
        void *plmn = (void*)env->GetByteArrayElements(jplmn,NULL);
        uint32_t plmn_len = env->GetArrayLength(jplmn);
        void *kasme = (void*)env->GetByteArrayElements(jkasme,NULL);
        void *autn = (void*)env->GetByteArrayElements(jautn,NULL);
        uint32_t autn_len = env->GetArrayLength(jautn);
        void *res = (void*)env->GetByteArrayElements(jres,NULL);

        OctetString o_opc = OctetString::FromArray((const uint8_t *)opc, opc_len);
        OctetString o_key = OctetString::FromArray((const uint8_t *)key, key_len);
        OctetString o_rand = OctetString::FromArray((const uint8_t *)rand, rand_len);
        OctetString o_autn = OctetString::FromArray((const uint8_t *)autn, autn_len);
        OctetString o_plmn = OctetString::FromArray((const uint8_t *)plmn, plmn_len);
        OctetString o_res;
        OctetString o_kasme;

        int ret = handle4gAuthentication(op_type, o_opc, o_key, o_rand, o_autn, o_plmn, o_res, o_kasme);

        memcpy(res, o_res.data(), o_res.length());
        memcpy(kasme, o_kasme.data(), o_kasme.length());
              
        env->ReleaseByteArrayElements(jopc, (jbyte*)opc,JNI_ABORT); 
        env->ReleaseByteArrayElements(jkey, (jbyte*)key,JNI_ABORT); 
        env->ReleaseByteArrayElements(jrand, (jbyte*)rand,JNI_ABORT); 
        env->ReleaseByteArrayElements(jautn, (jbyte*)autn,JNI_ABORT); 
        env->ReleaseByteArrayElements(jplmn, (jbyte*)plmn,JNI_ABORT);           
        env->ReleaseByteArrayElements(jres, (jbyte*)res,0);  
        env->ReleaseByteArrayElements(jkasme, (jbyte*)kasme,0); 
        
        return ret;
}


int handle5gAuthentication(int op_type, const OctetString &opc, const OctetString &key, const OctetString &supi, 
        const OctetString &rand, const OctetString &autn, const OctetString &snn, const OctetString &abba, 
        OctetString &res, OctetString &kseaf, OctetString &kamf)
{
    SqnManager sqnMng(5ull, 1ull << 28ull);
    
    OctetString receivedSQNxorAK = autn.subCopy(0, 6);
    OctetString receivedAMF = autn.subCopy(6, 2);
    OctetString receivedMAC = autn.subCopy(8, 8);

    int autnCheck = validateAutn(&sqnMng, op_type, opc, key, rand, autn);

    if (autnCheck == 0)
    {
        // Calculate milenage
        auto milenage = calculateMilenage(op_type, opc, key, sqnMng.getSqn(), rand, receivedAMF);
        auto ckIk = OctetString::Concat(milenage.ck, milenage.ik);
        auto sqnXorAk = OctetString::Xor(sqnMng.getSqn(), milenage.ak);

        res = CalculateResStar(ckIk, snn, rand, milenage.res);
        auto kausf = CalculateKAusfFor5gAka(milenage.ck, milenage.ik, snn, sqnXorAk);

        DeriveKeysSeafAmf(supi, snn, kausf, abba, kseaf, kamf);
    }

    return autnCheck;
}

JNIEXPORT int JNICALL Java_com_ailink_jni_CryptUtil_Handle5gAuthentication(JNIEnv *env, jobject obj, 
        jint op_type, jbyteArray jopc, jbyteArray jkey, jbyteArray jsupi, 
        jbyteArray jrand, jbyteArray jautn, jbyteArray jsnn, jbyteArray jabba, 
        jbyteArray jkseaf, jbyteArray jkamf, jbyteArray jres) {
        void *opc = (void*)env->GetByteArrayElements(jopc,NULL);
        uint32_t opc_len = env->GetArrayLength(jopc);
        void *key = (void*)env->GetByteArrayElements(jkey,NULL);
        uint32_t key_len = env->GetArrayLength(jkey);
        void *rand = (void*)env->GetByteArrayElements(jrand,NULL);
        uint32_t rand_len = env->GetArrayLength(jrand);
        void *snn = (void*)env->GetByteArrayElements(jsnn,NULL);
        uint32_t snn_len = env->GetArrayLength(jsnn);
        void *autn = (void*)env->GetByteArrayElements(jautn,NULL);
        uint32_t autn_len = env->GetArrayLength(jautn);
        void *abba = (void*)env->GetByteArrayElements(jabba,NULL);
        uint32_t abba_len = env->GetArrayLength(jabba);
        void *supi = (void*)env->GetByteArrayElements(jsupi,NULL);
        uint32_t supi_len = env->GetArrayLength(jsupi);
        void *res = (void*)env->GetByteArrayElements(jres,NULL);
        void *kseaf = (void*)env->GetByteArrayElements(jkseaf,NULL);
        void *kamf = (void*)env->GetByteArrayElements(jkamf,NULL);

        OctetString o_opc = OctetString::FromArray((const uint8_t *)opc, opc_len);
        OctetString o_key = OctetString::FromArray((const uint8_t *)key, key_len);
        OctetString o_rand = OctetString::FromArray((const uint8_t *)rand, rand_len);
        OctetString o_autn = OctetString::FromArray((const uint8_t *)autn, autn_len);
        OctetString o_snn = OctetString::FromArray((const uint8_t *)snn, snn_len);
        OctetString o_abba = OctetString::FromArray((const uint8_t *)abba, abba_len);
        OctetString o_supi = OctetString::FromArray((const uint8_t *)supi, supi_len);
        OctetString o_res;
        OctetString o_kseaf;
        OctetString o_kamf;

        int ret = handle5gAuthentication(op_type, o_opc, o_key, o_supi, o_rand, o_autn, o_snn, o_abba,
                o_res, o_kseaf, o_kamf);

        memcpy(res, o_res.data(), o_res.length());
        memcpy(kseaf, o_kseaf.data(), o_kseaf.length());
        memcpy(kamf, o_kamf.data(), o_kamf.length());
              
        env->ReleaseByteArrayElements(jopc, (jbyte*)opc,JNI_ABORT); 
        env->ReleaseByteArrayElements(jkey, (jbyte*)key,JNI_ABORT); 
        env->ReleaseByteArrayElements(jrand, (jbyte*)rand,JNI_ABORT); 
        env->ReleaseByteArrayElements(jautn, (jbyte*)autn,JNI_ABORT); 
        env->ReleaseByteArrayElements(jsnn, (jbyte*)snn,JNI_ABORT);    
        env->ReleaseByteArrayElements(jabba, (jbyte*)abba,JNI_ABORT);  
        env->ReleaseByteArrayElements(jsupi, (jbyte*)supi,JNI_ABORT);         
        env->ReleaseByteArrayElements(jres, (jbyte*)res,0);        
        env->ReleaseByteArrayElements(jkseaf, (jbyte*)kseaf,0);        
        env->ReleaseByteArrayElements(jkamf, (jbyte*)kamf,0);  
        
        return ret;
}
//
// This file is a part of UERANSIM open source project.
// Copyright (c) 2021 ALİ GÜNGÖR.
//
// The software and all associated files are licensed under GPL-3.0
// and subject to the terms and conditions defined in LICENSE file.
//

#include "crypt.hpp"
#include "eea2.hpp"
#include "eea3.hpp"
#include "eia2.hpp"
#include "mac.hpp"
#include "snow3g.hpp"
#include "uea2.hpp"
#include "zuc.hpp"

#include <stdexcept>
#include <cstring>

namespace crypto
{

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

void DeriveEpsNasKeys(uint32_t ciphering, uint32_t integrity, const char *k_amf, uint32_t kamf_len, uint8_t *kNasEnc, uint8_t *kNasInt)
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
    auto kdfEnc = crypto::CalculateKdfKey(o_kamf, 0x15, s1, 2);
    auto kdfInt = crypto::CalculateKdfKey(o_kamf, 0x15, s2, 2);

    OctetString keys_kNasEnc = kdfEnc.subCopy(16, 16);
    OctetString keys_kNasInt = kdfInt.subCopy(16, 16); 
    std::memcpy(kNasEnc, keys_kNasEnc.data(), keys_kNasEnc.length());
    std::memcpy(kNasInt, keys_kNasInt.data(), keys_kNasInt.length());
}

void DeriveKeysSeafAmf(const char *kausf, int ausf_len, const char *supi, uint32_t supi_len, const char *snn, uint32_t snn_len, const char *abba, uint32_t abba_len, char *k_seaf, char *k_amf)
{
    OctetString kSeaf{};
    OctetString kAmf{};
    std::string s_snn;
    std::string s_supi;
    std::string s_abba ;

    s_supi.assign(supi, supi_len);
    s_abba.assign(abba, abba_len);
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

void DeriveNasKeysC(uint32_t ciphering, uint32_t integrity, const char *k_amf, uint32_t kamf_len, uint8_t *kNasEnc, uint8_t *kNasInt)
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


void DeriveEpsNasKeysC(uint32_t ciphering, uint32_t integrity, const char *k_amf, uint32_t kamf_len, uint8_t *kNasEnc, uint8_t *kNasInt)
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
    auto kdfEnc = crypto::CalculateKdfKey(o_kamf, 0x15, s1, 2);
    auto kdfInt = crypto::CalculateKdfKey(o_kamf, 0x15, s2, 2);

    OctetString keys_kNasEnc = kdfEnc.subCopy(16, 16);
    OctetString keys_kNasInt = kdfInt.subCopy(16, 16); 
    std::memcpy(kNasEnc, keys_kNasEnc.data(), keys_kNasEnc.length());
    std::memcpy(kNasInt, keys_kNasInt.data(), keys_kNasInt.length());
}

OctetString CalculatePrfPrime(const OctetString &key, const OctetString &input, int outputLength)
{
    if (key.length() != 32)
        throw std::runtime_error("CalculatePrfPrime, 256-bit key expected");

    int round = outputLength / 32 + 1;
    if (round <= 0 || round > 254)
        throw std::runtime_error("CalculatePrfPrime, invalid outputLength value");

    std::vector<OctetString> T(round);

    for (int i = 0; i < round; i++)
    {
        OctetString s{};

        if (i == 0)
        {
            s.append(input);
            s.appendOctet(i + 1);
        }
        else
        {
            s.append(T[i - 1]);
            s.append(input);
            s.appendOctet(i + 1);
        }

        T[i] = HmacSha256(key, s);
    }

    OctetString res;
    for (auto &s : T)
        res.append(s);
    return res;
}

OctetString HmacSha256(const OctetString &key, const OctetString &input)
{
    std::vector<uint8_t> out(32);
    HmacSha256(out.data(), input.data(), input.length(), key.data(), key.length());
    return OctetString{std::move(out)};
}

OctetString CalculateKdfKey(const OctetString &key, int fc, OctetString *parameters, int numberOfParameter)
{
    OctetString inp;
    inp.appendOctet(fc);
    for (int i = 0; i < numberOfParameter; i++)
    {
        inp.append(parameters[i]);
        inp.appendOctet2(parameters[i].length());
    }
    return HmacSha256(key, inp);
}

OctetString CalculateKdfKey(const OctetString &key, int fc1, int fc2, OctetString *parameters, int numberOfParameter)
{
    OctetString inp;
    inp.appendOctet(fc1);
    inp.appendOctet(fc2);
    for (int i = 0; i < numberOfParameter; i++)
    {
        inp.append(parameters[i]);
        inp.appendOctet2(parameters[i].length());
    }
    return HmacSha256(key, inp);
}

OctetString EncodeKdfString(const std::string &string)
{
    // Todo normalize the string
    // V16.0.0 - B.2.1.2 Character string encoding
    // A character string shall be encoded to an octet string according to UTF-8 encoding rules as specified in
    // IETF RFC 3629 [24] and apply Normalization Form KC (NFKC) as specified in [37].
    return OctetString{std::vector<uint8_t>{string.c_str(), string.c_str() + string.length()}};
}

std::vector<uint32_t> Snow3g(const OctetString &key, const OctetString &iv, int length)
{
    std::vector<uint32_t> res(length);
    snow3g::Initialize(reinterpret_cast<const uint32_t *>(key.data()), reinterpret_cast<const uint32_t *>(iv.data()));
    snow3g::GenerateKeyStream(res.data(), length);
    return res;
}

std::vector<uint32_t> Zuc(const OctetString &key, const OctetString &iv, int length)
{
    std::vector<uint32_t> res(length);
    zuc::Initialize(key.data(), iv.data());
    zuc::GenerateKeyStream(res.data(), length);
    return res;
}

uint32_t ComputeMacUia2_c(signed char *pKey, uint32_t key_len, uint32_t count, uint32_t fresh, uint32_t dir, signed char *pData,
                        uint64_t length)
{
    return crypto::uea2::F9((const uint8_t *)pKey, count, fresh, dir, (uint8_t *)pData, length * 8);
}

uint32_t ComputeMacUia2(const uint8_t *pKey, uint32_t count, uint32_t fresh, uint32_t dir, const uint8_t *pData,
                        uint64_t length)
{
    return crypto::uea2::F9(pKey, count, fresh, dir, pData, length * 8);
}

void EncryptUea2_c(signed char *pKey, uint32_t key_len, uint32_t count, uint32_t bearer, uint32_t dir, signed char * pData, uint32_t length)
{
    crypto::uea2::F8((const uint8_t *)pKey, count, bearer, dir, (uint8_t *)pData, length * 8);
}

void EncryptUea2(const uint8_t *pKey, uint32_t count, uint32_t bearer, uint32_t dir, uint8_t *pData, uint32_t length)
{
    crypto::uea2::F8(pKey, count, bearer, dir, pData, length * 8);
}

void EncryptEea1(uint32_t count, int bearer, int direction, OctetString &message, const OctetString &key)
{
    EncryptUea2(key.data(), count, bearer, direction, message.data(), message.length());
}

void EncryptEea1_c(signed char *pKey, uint32_t key_len, uint32_t count, uint32_t bearer, uint32_t dir, signed char * pData, uint32_t length)
{
    EncryptUea2((const uint8_t *)pKey, count, bearer, dir, (uint8_t *)pData, length);
}

void DecryptEea1_c(signed char *pKey, uint32_t key_len, uint32_t count, uint32_t bearer, uint32_t dir, signed char * pData, uint32_t length)
{
    EncryptUea2((const uint8_t *)pKey, count, bearer, dir, (uint8_t *)pData, length);
}

void DecryptEea1(uint32_t count, int bearer, int direction, OctetString &message, const OctetString &key)
{
    EncryptEea1(count, bearer, direction, message, key);
}

uint32_t ComputeMacEia1_c(signed char * pKey, uint32_t key_len, uint32_t count, int bearer, int direction, signed char * pData, uint32_t length)
{
    uint32_t fresh = bearer << 27;
    return ComputeMacUia2((const uint8_t *)pKey, count, fresh, direction, (uint8_t *)pData, length);
}

uint32_t ComputeMacEia1(uint32_t count, int bearer, int direction, const OctetString &message, const OctetString &key)
{
    uint32_t fresh = bearer << 27;
    return ComputeMacUia2(key.data(), count, fresh, direction, message.data(), message.length());
}

void EncryptEea2_c(signed char *pKey, uint32_t key_len, uint32_t count, int bearer, int direction, signed char * pData, uint32_t length)
{
    eea2::Encrypt_c((const uint8_t *)pKey, count, bearer, direction, (uint8_t *)pData, length);
}

void EncryptEea2(uint32_t count, int bearer, int direction, OctetString &message, const OctetString &key)
{
    eea2::Encrypt(count, bearer, direction, message, key);
}

void DecryptEea2_c(signed char *pKey, uint32_t key_len, uint32_t count, int bearer, int direction, signed char * pData, uint32_t length)
{
    eea2::Decrypt_c((const uint8_t *)pKey, count, bearer, direction, (uint8_t *)pData, length);
}

void DecryptEea2(uint32_t count, int bearer, int direction, OctetString &message, const OctetString &key)
{
    eea2::Decrypt(count, bearer, direction, message, key);
}

uint32_t ComputeMacEia2_c(signed char *pKey, uint32_t key_len, uint32_t count, int bearer, int direction, signed char *pData, uint32_t length)
{
    OctetString key = OctetString{std::vector<uint8_t>{pKey, pKey+key_len }};
    OctetString message = OctetString{std::vector<uint8_t>{pData, pData+length }};
    return eia2::Compute(count, bearer, direction, message, key);
}

uint32_t ComputeMacEia2(uint32_t count, int bearer, int direction, const OctetString &message, const OctetString &key)
{
    return eia2::Compute(count, bearer, direction, message, key);
}

void EncryptEea3_c(signed char *pKey, uint32_t key_len, uint32_t count, int bearer, int direction, signed char * pData, uint32_t length)
{
    eea3::EEA3((const uint8_t *)pKey, count, bearer, direction, length * 8,
               reinterpret_cast<uint32_t *>(pData));
}

void EncryptEea3(uint32_t count, int bearer, int direction, OctetString &message, const OctetString &key)
{
    eea3::EEA3(key.data(), count, bearer, direction, message.length() * 8,
               reinterpret_cast<uint32_t *>(message.data()));
}

void DecryptEea3_c(signed char *pKey, uint32_t key_len, uint32_t count, int bearer, int direction, signed char * pData, uint32_t length)
{
    eea3::EEA3((const uint8_t *)pKey, count, bearer, direction, length * 8,
               reinterpret_cast<uint32_t *>(pData));
}

void DecryptEea3(uint32_t count, int bearer, int direction, OctetString &message, const OctetString &key)
{
    eea3::EEA3(key.data(), count, bearer, direction, message.length() * 8,
               reinterpret_cast<uint32_t *>(message.data()));
}

uint32_t ComputeMacEia3_c(signed char *pKey, uint32_t key_len, uint32_t count, int bearer, int direction, signed char * pData, uint32_t length)
{
    return eea3::EIA3((const uint8_t *)pKey, count, direction, bearer, length * 8,
                      reinterpret_cast<const uint32_t *>(pData));
}

uint32_t ComputeMacEia3(uint32_t count, int bearer, int direction, const OctetString &message, const OctetString &key)
{
    return eea3::EIA3(key.data(), count, direction, bearer, message.length() * 8,
                      reinterpret_cast<const uint32_t *>(message.data()));
}


void DeriveKeysSeafAmf_c(const char *kausf, int ausf_len, const char *supi, uint32_t supi_len, const char *snn, uint32_t snn_len, const char *abba, uint32_t abba_len, char *k_seaf, char *k_amf)
{
    OctetString kSeaf{};
    OctetString kAmf{};
    std::string s_snn;
    std::string s_supi;
    std::string s_abba ;

    s_supi.assign(supi, supi_len);
    s_abba.assign(abba, abba_len);
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

void CalculateCkPrimeIkPrime(const char *ck, int ck_len, const char* ik, int ik_len, const char *snn, int snn_len, const char *sqnXorAk, int sxa_len,
        char *ckPrime, int ckPrime_len, char *ikPrime, int ikPrime_len)
{
    std::string s_snn(snn) ;
    OctetString key = OctetString::Concat(OctetString::FromArray((const uint8_t *)ck, ck_len), OctetString::FromArray((const uint8_t *)ik, ik_len));
    OctetString s[2];
    s[0] = crypto::EncodeKdfString(s_snn);
    s[1] = OctetString::FromArray((const uint8_t *)sqnXorAk, sxa_len);

    auto res = crypto::CalculateKdfKey(key, 0x20, s, 2);

    OctetString keyfirst = res.subCopy(0, ck_len);
    OctetString keysecond = res.subCopy(ck_len);
    if (keyfirst.length() > ckPrime_len || keysecond.length() > ikPrime_len) {
        return;
    }

    std::memcpy(ckPrime, keyfirst.data(), keyfirst.length());
    std::memcpy(ikPrime, keysecond.data(), keysecond.length());
}


void CalculateMk(const char *ckPrime, int ckPrime_len, const char *ikPrime, int ikPrime_len, int type, const char *supi, char *mk, int mk_len)
{
    char s_input[50];
    sprintf(s_input, "EAP-AKA'%d-%s", type, supi);
    OctetString key = OctetString::Concat(OctetString::FromArray((const uint8_t *)ikPrime, ikPrime_len), OctetString::FromArray((const uint8_t *)ckPrime, ckPrime_len));
    OctetString input = OctetString::FromAscii(s_input);

    OctetString ret = crypto::CalculatePrfPrime(key, input, 208);

    std::memcpy(mk, ret.data(), mk_len);
}

} // namespace crypto

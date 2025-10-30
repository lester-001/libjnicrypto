//
// This file is a part of UERANSIM open source project.
// Copyright (c) 2021 ALİ GÜNGÖR.
//
// The software and all associated files are licensed under GPL-3.0
// and subject to the terms and conditions defined in LICENSE file.
//

#pragma once

#include <utils/octet_string.hpp>

namespace crypto
{

OctetString CalculateResStar(const OctetString &key, const OctetString &snn, const OctetString &rand,
                             const OctetString &res);
                             
void DeriveKeysSeafAmf(const OctetString &supi, const OctetString &snn, 
    const OctetString &kausf, const OctetString &abba, OctetString &kseaf, OctetString &kAmf);
OctetString CalculateKAusfFor4gAka(const OctetString &ck, const OctetString &ik, const OctetString &snn,
                                   const OctetString &sqnXorAk);


OctetString CalculateKAusfFor5gAka(const OctetString &ck, const OctetString &ik, const OctetString &snn,
                                   const OctetString &sqnXorAk);
void DeriveNasKeys(uint32_t ciphering, uint32_t integrity, const char *k_amf, uint32_t kamf_len, uint8_t *kNasEnc, uint8_t *kNasInt);
void DeriveEpsNasKeys(uint32_t ciphering, uint32_t integrity, const char *k_amf, uint32_t kamf_len, uint8_t *kNasEnc, uint8_t *kNasInt);

void DeriveKeysSeafAmf(const char *kausf, int ausf_len, const char *supi, uint32_t supi_len, const char *snn, uint32_t snn_len, const char *abba, uint32_t abba_len, char *k_seaf, char *k_amf);

uint32_t ComputeMacEia2(signed char *pKey, uint32_t key_len, uint32_t count, int bearer, int direction, signed char *pData, uint32_t length);

void DecryptEea1(signed char *pKey, uint32_t key_len, uint32_t count, uint32_t bearer, uint32_t dir, signed char * pData, uint32_t length);

uint32_t ComputeMacEia3(signed char *pKey, uint32_t key_len, uint32_t count, int bearer, int direction, signed char * pData, uint32_t length);

void EncryptEea2(signed char *pKey, uint32_t key_len, uint32_t count, int bearer, int direction, signed char * pData, uint32_t length);

void DecryptEea2(signed char *pKey, uint32_t key_len, uint32_t count, int bearer, int direction, signed char * pData, uint32_t length);

void EncryptEea3(signed char *pKey,uint32_t count, int bearer, int direction, signed char * pData, uint32_t length);

void DecryptEea3(signed char *pKey, uint32_t count, int bearer, int direction, signed char * pData, uint32_t length);

/* KDF and MAC etc. */
OctetString CalculatePrfPrime(const OctetString &key, const OctetString &input, int outputLength);
OctetString HmacSha256(const OctetString &key, const OctetString &input);
OctetString CalculateKdfKey(const OctetString &key, int fc, OctetString *parameters, int numberOfParameter);
OctetString CalculateKdfKey(const OctetString &key, int fc1, int fc2, OctetString *parameters, int numberOfParameter);
OctetString EncodeKdfString(const std::string &string);

/* Snow3G etc. */
std::vector<uint32_t> Snow3g(const OctetString &key, const OctetString &iv, int length);
std::vector<uint32_t> Zuc(const OctetString &key, const OctetString &iv, int length);

uint32_t ComputeMacUia2_c(signed char *pKey, uint32_t key_len, uint32_t count, uint32_t fresh, uint32_t dir, signed char *pData,
                        uint64_t length);

void EncryptUea2_c(signed char *pKey, uint32_t key_len, uint32_t count, uint32_t bearer, uint32_t dir, signed char *pData, uint32_t length);

/* UIA2 and UEA2 */
uint32_t ComputeMacUia2(const uint8_t *pKey, uint32_t count, uint32_t fresh, uint32_t dir, const uint8_t *pData,
                        uint64_t length);
void EncryptUea2(const uint8_t *pKey, uint32_t count, uint32_t bearer, uint32_t dir, uint8_t *pData, uint32_t length);

uint32_t ComputeMacEia2_c(signed char * *pKey, uint32_t key_len, uint32_t count, int bearer, int direction, signed char *pData, uint32_t length);

void DeriveKeysSeafAmf_c(const char *kausf, int ausf_len, const char *supi, uint32_t supi_len, const char *snn, uint32_t snn_len, const char *abba, uint32_t abba_len, char *k_seaf, char *k_amf);
void DeriveNasKeysC(uint32_t ciphering, uint32_t integrity, const char *k_amf, uint32_t kamf_len, uint8_t *kNasEnc, uint8_t *kNasInt);
void DeriveEpsNasKeysC(uint32_t ciphering, uint32_t integrity, const char *k_amf, uint32_t kamf_len, uint8_t *kNasEnc, uint8_t *kNasInt);

/* EEA1 and EIA1 */
void EncryptEea1_c(signed char *pKey, uint32_t key_len, uint32_t count, uint32_t bearer, uint32_t dir, signed char *pData, uint32_t length);
void DecryptEea1_c(signed char *pKey, uint32_t key_len, uint32_t count, uint32_t bearer, uint32_t dir, signed char *pData, uint32_t length);
uint32_t ComputeMacEia1_c(signed char *pKey, int key_len, uint32_t count, int bearer, int direction, signed char *pData, uint32_t length);
void EncryptEea1(uint32_t count, int bearer, int direction, OctetString &message, const OctetString &key);
void DecryptEea1(uint32_t count, int bearer, int direction, OctetString &message, const OctetString &key);
uint32_t ComputeMacEia1(uint32_t count, int bearer, int direction, const OctetString &message, const OctetString &key);

/* EEA2 and EIA2 */
void EncryptEea2_c(signed char *pKey, uint32_t key_len, uint32_t count, int bearer, int direction, signed char *pData, uint32_t length);
void DecryptEea2_c(signed char *pKey, uint32_t key_len, uint32_t count, int bearer, int direction, signed char *pData, uint32_t length);
uint32_t ComputeMacEia2_c(signed char *pKey, uint32_t key_len, uint32_t count, int bearer, int direction, signed char *pData, uint32_t length);
void EncryptEea2(uint32_t count, int bearer, int direction, OctetString &message, const OctetString &key);
void DecryptEea2(uint32_t count, int bearer, int direction, OctetString &message, const OctetString &key);
uint32_t ComputeMacEia2(uint32_t count, int bearer, int direction, const OctetString &message, const OctetString &key);

/* EEA3 and EIA3 */
void EncryptEea3_c(signed char *pKey, uint32_t key_len, uint32_t count, int bearer, int direction, signed char *pData, uint32_t length);
void DecryptEea3_c(signed char *pKey, uint32_t key_len, uint32_t count, int bearer, int direction, signed char *pData, uint32_t length);
uint32_t ComputeMacEia3_c(signed char *pKey, uint32_t key_len, uint32_t count, int bearer, int direction, signed char *pData, uint32_t length);
void EncryptEea3(uint32_t count, int bearer, int direction, OctetString &message, const OctetString &key);
void DecryptEea3(uint32_t count, int bearer, int direction, OctetString &message, const OctetString &key);
uint32_t ComputeMacEia3(uint32_t count, int bearer, int direction, const OctetString &message, const OctetString &key);


} // namespace crypt
#include <jni.h>
#include <cstring>
#include <time.h>
#include "gtpproxy.hpp"
#include "lib/gtp/gtp.hpp"
#include <utils/common.hpp>
#include <utils/io.hpp>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sched.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/time.h>

using namespace gtp;

JNIEXPORT jint JNICALL Java_com_ailink_jni_GtpProxy_switchNamespace
  (JNIEnv *env, jobject obj, jstring nsPath) {
    const char *path = env->GetStringUTFChars(nsPath, 0);
    int fd = open(path, O_RDONLY);
    if (fd == -1) return -1;
    
    int result = setns(fd, CLONE_NEWNET);
    close(fd);
    env->ReleaseStringUTFChars(nsPath, path);
    return result;
}

JNIEXPORT void JNICALL Java_com_ailink_jni_GtpProxy_Start(JNIEnv *env, jobject obj, jint jgnbid, jstring jlocalIp)
{
    const char* localIp = env->GetStringUTFChars(jlocalIp, NULL);
    int localIp_len = env->GetStringUTFLength(jlocalIp);

    std::string s_localIp;    
    s_localIp.reserve(localIp_len + 1);
    memcpy(s_localIp.data(), localIp, localIp_len);
    s_localIp.data()[localIp_len] = '\0';


    GtpProxyMng::getInstance().addGtpProxy(jgnbid, s_localIp);

    env->ReleaseStringUTFChars(jlocalIp, localIp);
}

JNIEXPORT void JNICALL Java_com_ailink_jni_GtpProxy_Stop(JNIEnv *env, jobject obj, jint jgnbid)
{
    GtpProxyMng::getInstance().removeGtpProxy(jgnbid);
}

JNIEXPORT void JNICALL Java_com_ailink_jni_GtpProxy_AddUeContext(JNIEnv *env, jobject obj, jint jgnbid, jint jueid, jlong dlAmbr, jlong ulAmbr)
{
    GtpProxy* proxy = GtpProxyMng::getInstance().getProxy(jgnbid);
    if (proxy) 
    {
        proxy->addUeContext(jueid, dlAmbr, ulAmbr);
    }
}

JNIEXPORT void JNICALL Java_com_ailink_jni_GtpProxy_AddSipContext(JNIEnv *env, jobject obj, jint jgnbid, jint jueid, jint psi, jstring jueip, jstring jimsip)
{
    const char* ueip = env->GetStringUTFChars(jueip, NULL);
    const char* imsip = env->GetStringUTFChars(jimsip, NULL);

    std::string s_ueip(ueip);   
    std::string s_imsip(imsip);

    printf("Adding SIP context for UE %d  %s\n", jueid, s_ueip.c_str(), s_imsip.c_str());
    GtpProxy* proxy = GtpProxyMng::getInstance().getProxy(jgnbid);
    if (proxy) 
    {
        proxy->addSipContext(jueid, s_ueip, s_imsip);
    }
    
    env->ReleaseStringUTFChars(jueip, ueip);
    env->ReleaseStringUTFChars(jimsip, imsip);
}

JNIEXPORT void JNICALL Java_com_ailink_jni_GtpProxy_AddUeSession(JNIEnv *env, jobject obj, jint jgnbid, jint jueid,
    jint psi, jint qfi, jint local_teid, jint remote_teid, jstring jremoteip, jlong dlAmbr, jlong ulAmbr)
{
    GtpProxy* proxy = GtpProxyMng::getInstance().getProxy(jgnbid);
    
    const char* remoteip = env->GetStringUTFChars(jremoteip, NULL);
  
    int remoteip_len = env->GetStringUTFLength(jremoteip);

    std::string s_remoteip;    
    s_remoteip.reserve(remoteip_len + 1);
    
    memcpy(s_remoteip.data(), remoteip, remoteip_len);
    s_remoteip.data()[remoteip_len] = '\0';

    if (proxy) 
    {
        proxy->addSession(jueid, psi, qfi, local_teid, remote_teid, s_remoteip, dlAmbr, ulAmbr);
    }
    
    
    env->ReleaseStringUTFChars(jremoteip, remoteip);
}

JNIEXPORT void JNICALL Java_com_ailink_jni_GtpProxy_SendUeData(JNIEnv *env, jobject obj, jint jgnbid, jint jueid,
    jint psi, jbyteArray jdata)
{
    uint8_t *data = (uint8_t *)env->GetByteArrayElements(jdata,NULL);
    uint32_t data_len = env->GetArrayLength(jdata);
    
    GtpProxy* proxy = GtpProxyMng::getInstance().getProxy(jgnbid);
    if (proxy) 
    {
        proxy->sendUeData(jueid, psi, data, data_len);
    }

    env->ReleaseByteArrayElements(jdata, (jbyte*)data,JNI_ABORT);
}

JNIEXPORT jbyteArray JNICALL Java_com_ailink_jni_GtpProxy_GetUeData(JNIEnv *env, jobject obj, jint jgnbid, jint jueid)
{
    GtpProxy* proxy = GtpProxyMng::getInstance().getProxy(jgnbid);
    if (proxy == nullptr) 
    {
        printf("GtpProxy is not found");
        return NULL; // 内存不足
    }
    
    int cDataLength = proxy->recvUeDataSize(jueid);
    if (cDataLength == 0)
    {
        return NULL;
    }
    
    // 创建 Java byte[] 数组
    jbyteArray javaArray = env->NewByteArray(cDataLength);
    if (javaArray == NULL) {
        return NULL; // 内存不足
    }
    
    uint8_t *cData = (uint8_t *)env->GetByteArrayElements(javaArray,NULL);

    cDataLength = proxy->recvUeData(jueid, cData);

    // 将 C 数据复制到 Java 数组
    env->SetByteArrayRegion(javaArray, 0, cDataLength, (jbyte*)cData);
    return javaArray;
}

JNIEXPORT jbyteArray JNICALL Java_com_ailink_jni_GtpProxy_GetUeDataWithTimeout(JNIEnv *env, jobject obj, jint jgnbid, jint jueid, jint timeout)
{
    GtpProxy* proxy = GtpProxyMng::getInstance().getProxy(jgnbid);
    if (proxy == nullptr) 
    {
        printf("GtpProxy is not found");
        return NULL; // 内存不足
    }
    
    int cDataLength = 0;
    int64_t timestampStart = utils::CurrentTimeMillis();
    int64_t timestampCur = 0, ts = timeout * 1000;
    do 
    {
        cDataLength = proxy->recvUeDataSize(jueid);
        if (cDataLength != 0)
        {
            break;
        }
        utils::Sleep(100);
        timestampCur = utils::CurrentTimeMillis();

    } while (timestampCur - timestampStart < ts);
    
    // 创建 Java byte[] 数组
    jbyteArray javaArray = env->NewByteArray(cDataLength);
    if (javaArray == NULL) {
        return NULL; // 内存不足
    }
    
    uint8_t *cData = (uint8_t *)env->GetByteArrayElements(javaArray,NULL);

    cDataLength = proxy->recvUeData(jueid, cData);

    // 将 C 数据复制到 Java 数组
    env->SetByteArrayRegion(javaArray, 0, cDataLength, (jbyte*)cData);
    return javaArray;
}

bool isSipMsg(uint8_t *data, int data_len)
{
    if (data_len < 20) 
    {
        return false;
    }

    uint8_t proto = data[9];
    uint8_t *msg = nullptr;

    if (proto == 0x11)
    {
        uint8_t rtp = data[28];
        if (rtp == 0x80)
        {
            return false;
        }

        msg = data + 28;
    }
    else if (proto == 0x06)
    {
        msg = data + 40;
    }
    else 
    {
        return false;
    }
    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct timespec start;    
    // 使用单调时钟
    clock_gettime(CLOCK_MONOTONIC, &start);

    time_t now = time(NULL);
    struct tm *local = localtime(&now);
    
    printf("本地时间: %ld %ld  %d-%02d-%02d %02d:%02d:%02d %s\n", start.tv_sec, start.tv_nsec, 
       local->tm_year + 1900, local->tm_mon + 1, local->tm_mday,
       local->tm_hour, local->tm_min, local->tm_sec, msg);

    if (strncasecmp((char*)msg, "SIP/2.0", 7) == 0)
    {
        return true;
    }
    if (strncasecmp((char*)msg, "ACK", 3) == 0)
    {
        return true;
    }
    if (strncasecmp((char*)msg, "BYE", 3) == 0)
    {
        return true;
    }
    if (strncasecmp((char*)msg, "CANCEL", 6) == 0)
    {
        return true;
    }
    if (strncasecmp((char*)msg, "REGISTER", 8) == 0)
    {
        return true;
    }
    if (strncasecmp((char*)msg, "OPTIONS", 7) == 0)
    {
        return true;
    }
    if (strncasecmp((char*)msg, "SUBSCRIBE", 9) == 0)
    {
        return true;
    }
    if (strncasecmp((char*)msg, "UPDATE", 6) == 0)
    {
        return true;
    }
    if (strncasecmp((char*)msg, "PRACK", 5) == 0)
    {
        return true;
    }
    if (strncasecmp((char*)msg, "INFO", 4) == 0)
    {
        return true;
    }
    if (strncasecmp((char*)msg, "NOTIFY", 6) == 0)
    {
        return true;
    }
    if (strncasecmp((char*)msg, "MESSAGE", 7) == 0)
    {
        return true;
    }
    if (strncasecmp((char*)msg, "REFER", 5) == 0)
    {
        return true;
    }
    if (strncasecmp((char*)msg, "PUBLISH", 7) == 0)
    {
        return true;
    }
    if (strncasecmp((char*)msg, "INVITE", 6) == 0)
    {
        return true;
    }

    return false; 
}

JNIEXPORT jbyteArray JNICALL Java_com_ailink_jni_GtpProxy_GetSipMsgWithTimeout(JNIEnv *env, jobject obj, jint jgnbid, jint jueid, jint timeout)
{
    GtpProxy* proxy = GtpProxyMng::getInstance().getProxy(jgnbid);
    if (proxy == nullptr) 
    {
        printf("GtpProxy is not found");
        return NULL; // 内存不足
    }
    
    int cDataLength = 0;
    int64_t timestampStart = utils::CurrentTimeMillis();
    int64_t timestampCur = 0, ts = timeout * 1000;
    uint8_t *cData = NULL;
    jbyteArray javaArray;
    do
    {
        do 
        {
            cDataLength = proxy->recvUeDataSize(jueid);
            if (cDataLength != 0)
            {
                break;
            }
            utils::Sleep(100);
            timestampCur = utils::CurrentTimeMillis();

        } while (timestampCur - timestampStart < ts);
        
        if (cDataLength == 0)
        {
            return NULL; // 内存不足
        }
        
        // 创建 Java byte[] 数组
        javaArray = env->NewByteArray(cDataLength);
        if (javaArray == NULL) {
            return NULL; // 内存不足
        }
        
        cData = (uint8_t *)env->GetByteArrayElements(javaArray,NULL);

        cDataLength = proxy->recvUeData(jueid, cData);
        if (isSipMsg(cData, cDataLength) != true)
        {
            env->ReleaseByteArrayElements(javaArray, (jbyte *)cData, 0);
            cDataLength = 0;
        }
        else
        {
            break;
        }
        timestampCur = utils::CurrentTimeMillis();
    } while  (timestampCur - timestampStart < ts);

    if (cDataLength == 0) {
        return NULL; // 内存不足
    }
    
    uint8_t proto = cData[9];
    int offset = 0;
    if (proto == 0x11)
    {
        offset = 28;
    }
    else if (proto == 0x06)
    {
        offset = 40;
    }
    else 
    {
        return NULL;
    }

    // 将 C 数据复制到 Java 数组
    env->SetByteArrayRegion(javaArray, 0, cDataLength - offset, (jbyte*)(cData + offset));
    return javaArray;
}

JNIEXPORT void JNICALL Java_com_ailink_jni_GtpProxy_SendSipMsg(JNIEnv *env, jobject obj, jint jgnbid, jint jueid,
    jint psi, jint proto, jbyteArray jdata)
{
    uint8_t *data = (uint8_t *)env->GetByteArrayElements(jdata,NULL);
    uint32_t data_len = env->GetArrayLength(jdata);
    
    GtpProxy* proxy = GtpProxyMng::getInstance().getProxy(jgnbid);
    if (proxy) 
    {
        proxy->sendSipMsg(jueid, psi, proto, data, data_len);
    }

    env->ReleaseByteArrayElements(jdata, (jbyte*)data,JNI_ABORT);
}
#include <jni.h>
#include <cstring>
#include "gtpproxy.hpp"
#include "lib/gtp/gtp.hpp"

using namespace gtp;

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

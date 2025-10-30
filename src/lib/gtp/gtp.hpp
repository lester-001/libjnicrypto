
#pragma once

#include "types.hpp"
#include "task.hpp"
#include <unordered_map>

#include <lib/app/cli_cmd.hpp>
#include <lib/app/monitor.hpp>
#include <utils/logger.hpp>
#include <utils/network.hpp>
#include <utils/nts.hpp>
#include <shared_mutex>

namespace gtp
{

struct SipContext
{
    int ueid;
    OctetString ueip{};
    OctetString imsip{};
};

class GtpProxy
{
  private:
    TaskBase *taskBase;


    typedef std::deque<NmGtpPayload *> GtpPayloadQueue;
    typedef struct GtpPayloadQueueEntry
    {
        GtpPayloadQueue *queue;
        std::shared_mutex rw_mutex;
    } GtpPayloadQueueEntry;
    
    std::mutex mutex{};
    std::unordered_map<int, GtpPayloadQueueEntry *> uemsgQueue;

    std::shared_mutex rw_mutex;
    
    std::unordered_map<int, SipContext *> ueSipContext;
  public:
    GtpProxy(GtpConfig config, app::INodeListener *nodeListener, NtsTask *cliCallbackTask);
    virtual ~GtpProxy();

  public:
    void start();
    void addUeContext(int ueid, long dlAmbr, long ulAmbr);
    void addSession(int ueid, int psi, int qfi, int local_teid, int remote_teid, std::string &remoteip, long dlAmbr, long ulAmbr);

    void addSipContext(int ueid, std::string &ueip, std::string &imsip);

    void sendUeData(int ueid, int psi, uint8_t *buffer, size_t size);
    int recvUeData(int ueid, uint8_t *buffer);
    int recvUeDataSize(int ueid);

    void sendSipMsg(int ueid, int psi, int proto, uint8_t *buffer, size_t size);

    void addGtpPayload(int ueid, OctetString &payload);
};


class GtpProxyMng {
    public:
        // 删除拷贝构造函数和赋值运算符
        GtpProxyMng(const GtpProxyMng&) = delete;
        GtpProxyMng& operator=(const GtpProxyMng&) = delete;
    
        // 获取单例实例的静态方法
        static GtpProxyMng& getInstance() {
            static GtpProxyMng instance; // C++11保证静态局部变量初始化线程安全
            return instance;
        }

        bool addGtpProxy(int gnbid, std::string &gtpIp);  
        void removeGtpProxy(int gnbid);
        GtpProxy* getProxy(int gnbid);
    
    private:
        std::unordered_map<int, GtpProxy*> mapGtpProxy;
        GtpProxyMng() {} // 私有构造函数
    };

} // namespace nr::gnb
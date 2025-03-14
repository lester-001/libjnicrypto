
#pragma once

#include "types.hpp"
#include <unordered_map>

#include <lib/app/cli_cmd.hpp>
#include <lib/app/monitor.hpp>
#include <utils/logger.hpp>
#include <utils/network.hpp>
#include <utils/nts.hpp>

namespace gtp
{

class GtpProxy
{
  private:
    TaskBase *taskBase;

  public:
    GtpProxy(GtpConfig config, app::INodeListener *nodeListener, NtsTask *cliCallbackTask);
    virtual ~GtpProxy();

  public:
    void start();
    void addUeContext(int ueid, long dlAmbr, long ulAmbr);
    void addSession(int ueid, int psi, int qfi, int local_teid, int remote_teid, std::string &remoteip, long dlAmbr, long ulAmbr);
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
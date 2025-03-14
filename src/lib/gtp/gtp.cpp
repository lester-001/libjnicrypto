
#include "gtp.hpp"
#include "task.hpp"

#include <utils/common.hpp>
#include <utils/io.hpp>


namespace gtp
{

GtpProxy::GtpProxy(GtpConfig config, app::INodeListener *nodeListener, NtsTask *cliCallbackTask)
{
    auto *base = new TaskBase();
    base->config = config;
    base->logBase = new LogBase("logs/" + config.name + ".log");
    base->nodeListener = nodeListener;
    base->cliCallbackTask = cliCallbackTask;

    base->gtpTask = new GtpTask(base);

    taskBase = base;
}

GtpProxy::~GtpProxy()
{
    taskBase->gtpTask->quit();

    delete taskBase->gtpTask;
    delete taskBase->logBase;

    delete taskBase;
}

void GtpProxy::start()
{
    taskBase->gtpTask->start();
}

void GtpProxy::addUeContext(int ueid, long dlAmbr, long ulAmbr)
{
    AggregateMaximumBitRate ambr{dlAmbr, ulAmbr};
    auto *w = new NmGnbNgapToGtp(NmGnbNgapToGtp::UE_CONTEXT_UPDATE);
    w->update = std::make_unique<GtpUeContextUpdate>(true, ueid, ambr);
    taskBase->gtpTask->push(w);
}

void GtpProxy::addSession(int ueid, int psi, int qfi, int local_teid, int remote_teid, std::string &remoteip, long dlAmbr, long ulAmbr)
{
    AggregateMaximumBitRate ambr{dlAmbr, ulAmbr};
    auto *resource = new PduSessionResource(ueid, psi, qfi);


    resource->sessionAmbr = ambr;

    resource->downTunnel.address = utils::IpToOctetString(taskBase->config.gtpIp);
    resource->downTunnel.teid = local_teid;
    resource->upTunnel.teid = remote_teid;
    resource->upTunnel.address = utils::IpToOctetString(remoteip);

    printf("addSession %s %s\n", remoteip.c_str(), resource->upTunnel.address.toHexString().c_str());

    auto *w = new NmGnbNgapToGtp(NmGnbNgapToGtp::SESSION_CREATE);
    w->resource = resource;
    taskBase->gtpTask->push(w);
}

bool GtpProxyMng::addGtpProxy(int gnbid, std::string &gtpIp)
{    
    GtpConfig config;
    config.gnbid = gnbid;
    config.name = "gtpproxy-" + std::to_string(gnbid); 

    int version = utils::GetIpVersion(gtpIp.c_str());
    if (version == 6 || version == 4)
    {
        config.gtpIp = gtpIp.c_str();
    }

    auto ip4FromIf = io::GetIp4OfInterface(gtpIp);
    if (config.gtpIp.empty() && !ip4FromIf.empty())
    {
        config.gtpIp = ip4FromIf;
    }

    auto ip6FromIf = io::GetIp6OfInterface(gtpIp);
    if (config.gtpIp.empty() && !ip6FromIf.empty())
    {
        config.gtpIp = ip6FromIf;
    }    

    GtpProxy *proxy = new GtpProxy(config, nullptr, nullptr);

    proxy->start();

    mapGtpProxy[gnbid] = proxy;

    return true;
}
void GtpProxyMng::removeGtpProxy(int gnbid)
{
    GtpProxy *proxy = mapGtpProxy[gnbid];

    mapGtpProxy.erase(gnbid);

    if (proxy != nullptr) 
    {
        delete proxy;
    }

}
GtpProxy* GtpProxyMng::getProxy(int gnbid)
{
    return mapGtpProxy[gnbid];
}
} // namespace nr::gnb

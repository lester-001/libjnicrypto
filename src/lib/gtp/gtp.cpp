
#include "gtp.hpp"
#include "task.hpp"

#include <utils/common.hpp>
#include <utils/io.hpp>
#include <cstring>
#include <utils/constants.hpp>


namespace gtp
{

GtpProxy::GtpProxy(GtpConfig config, app::INodeListener *nodeListener, NtsTask *cliCallbackTask)
{
    auto *base = new TaskBase();
    base->config = config;
    base->logBase = new LogBase("logs/" + config.name + ".log");
    base->nodeListener = nodeListener;
    base->cliCallbackTask = cliCallbackTask;

    base->gtpTask = new GtpTask(base, this);

    taskBase = base;
}

GtpProxy::~GtpProxy()
{
    taskBase->gtpTask->quit();
    delete taskBase->gtpTask;
    delete taskBase->logBase;

    delete taskBase;

    for (const auto& [key, queue] : uemsgQueue) 
    {
        GtpPayloadQueueEntry *msgQueue = queue;
        while (msgQueue && msgQueue->queue &&!msgQueue->queue->empty()) {
            NmGtpPayload *val = msgQueue->queue->front();
            msgQueue->queue->pop_front();
            // 处理 val
            delete val;
        }

        delete msgQueue->queue;
        delete queue;
    }

    printf("GtpProxy::~GtpProxy()\n");
}

void GtpProxy::start()
{
    taskBase->gtpTask->start();
}

void GtpProxy::addUeContext(int ueid, long dlAmbr, long ulAmbr)
{
    GtpPayloadQueueEntry *msgQueue = new GtpPayloadQueueEntry;

    AggregateMaximumBitRate ambr{dlAmbr, ulAmbr};
    auto *w = new NmGnbNgapToGtp(NmGnbNgapToGtp::UE_CONTEXT_UPDATE);
    w->update = std::make_unique<GtpUeContextUpdate>(true, ueid, ambr, msgQueue);
    taskBase->gtpTask->push(w);

    msgQueue->queue = new GtpPayloadQueue;
    uemsgQueue[ueid] = msgQueue;
    
    printf("addUeContext. UE[%d]\n", ueid);
}

void GtpProxy::addSession(int ueid, int psi, int qfi, int local_teid, int remote_teid, std::string &remoteip, long dlAmbr, long ulAmbr)
{
    AggregateMaximumBitRate ambr{dlAmbr, ulAmbr};
    auto *resource = new PduSessionResource(ueid, psi, qfi);

    printf("addSession. UE[%d] PSI[%d]\n", ueid, psi);

    resource->sessionAmbr = ambr;

    resource->downTunnel.address = utils::IpToOctetString(taskBase->config.gtpIp);
    resource->downTunnel.teid = local_teid;
    resource->upTunnel.teid = remote_teid;
    resource->upTunnel.address = utils::IpToOctetString(remoteip);


    auto *w = new NmGnbNgapToGtp(NmGnbNgapToGtp::SESSION_CREATE);
    w->resource = resource;
    taskBase->gtpTask->push(w);
}

void GtpProxy::addSipContext(int ueid, std::string &ueip, std::string &imsip)
{
    SipContext *context = new SipContext;
    context->imsip = utils::IpToOctetString(imsip);
    context->ueip = utils::IpToOctetString(ueip);
    context->ueid = ueid;

    ueSipContext[ueid] = context;
    printf("addSipContext ueid %d %s %s\n", ueid, context->ueip.toHexString().c_str(), context->imsip.toHexString().c_str());
}
long  net_checksum_add(uint8_t * buf, int len)
{
    long sum = 0;
    int i;

    for (i = 0; i < len; i++) {
        if ((i & 1) == 1) {
            sum += buf[i];
        }
        else {
            sum +=buf[i] << 8;
        }
    }
    return sum;
}

long calculateChecksumTCPUDP(uint8_t * buf, int len)
{
    int length = len;

    long sum = 0;
    short csum_offset;

    int proto = buf[9];

    switch (proto) {
        case 1:
    	    csum_offset = 2;
    	    break;
        case 6:
    	    csum_offset = 16;
    	    break;
        case 17:
    	    csum_offset = 6;
    	    break;
        default:
    	    return 0;
    }
    
    if (length < csum_offset+2)
	    return 0;

    int hlen  = 20;
    buf[hlen+csum_offset]   = 0;
    buf[hlen+csum_offset+1] = 0;
    
    //byte[] payload0 = Arrays.copyOfRange(buf, 20, 22);
    
    sum += net_checksum_add(buf + 20, length - 20);         // payload

    if (proto != 1) {
        sum += net_checksum_add(buf + 12, 8);            // src + dst address
        sum += proto + length - 20;                        // protocol & length
    }

    while ((sum>>16) != 0) {
	    sum = (sum & 0xFFFF)+(sum >> 16);
    }
    sum = ~sum;
    sum = sum & 0xFFFF;
    
    return sum;
  }
void GtpProxy::sendSipMsg(int ueid, int psi, int proto, uint8_t *buffer, size_t size)
{
    std::vector<uint8_t> v(size);
    std::memcpy(v.data(), buffer, size);
    OctetString ret;
    OctetString msg ;
    OctetString sipmsg (std::move(v));

    switch (proto)
    {
    case 17:
    {
        uint8_t data[] = {0x45, 0x00, 0x00, 0x00, 0x05, 0xdf, 0x00, 0x00, 0xFf};
        int len = sizeof(data);
        std::vector<uint8_t> header(len);
        std::memcpy(header.data(), data, len);

        msg = OctetString (std::move(header));
        SipContext *context = ueSipContext[ueid];
        msg.appendOctet(proto & 0xFF);
        msg.appendOctet(0);
        msg.appendOctet(0);
        msg.append(context->ueip);
        msg.append(context->imsip);
        msg.appendOctet(0x13);
        msg.appendOctet(0xc4);
        msg.appendOctet(0x13);
        msg.appendOctet(0xc4);
        msg.appendOctet2((int)(size + 8));
        msg.appendOctet(0);
        msg.appendOctet(0);


        break;        
    }
    
    default:
        break;
    }


    ret = OctetString::Concat(msg, sipmsg);

    uint16_t checksum = calculateChecksumTCPUDP(ret.data(), ret.length() );


    ret.data()[2] = (static_cast<uint8_t>(ret.length() >> 8 & 0xFF));
    ret.data()[3] = (static_cast<uint8_t>(ret.length() & 0xFF));

    ret.data()[26] = (static_cast<uint8_t>(checksum >> 8 & 0xFF));
    ret.data()[27] = (static_cast<uint8_t>(checksum & 0xFF));

    checksum = ::calculate_checksum(ret.data(), 20);

    ret.data()[10] = (static_cast<uint8_t>(checksum >> 8 & 0xFF));
    ret.data()[11] = (static_cast<uint8_t>(checksum & 0xFF));

    auto *w = new NmGnbNgapToGtp(NmGnbNgapToGtp::DATA_PDU_DELIVERY);
    w->ueId =ueid;
    w->psi = psi;
    w->data.append(ret);

    taskBase->gtpTask->push(w);
}

void GtpProxy::sendUeData(int ueid, int psi, uint8_t *buffer, size_t size)
{
    std::vector<uint8_t> v(size);
    std::memcpy(v.data(), buffer, size);

    auto *w = new NmGnbNgapToGtp(NmGnbNgapToGtp::DATA_PDU_DELIVERY);
    w->ueId =ueid;
    w->psi = psi;
    w->data = OctetString{std::move(v)};

    taskBase->gtpTask->push(w);
}

int GtpProxy::recvUeDataSize(int ueid)
{
    int size = 0;

    GtpPayloadQueueEntry *queue = uemsgQueue[ueid];
/*
    uint64_t timestampStart = utils::CurrentTimeMillis();
    uint64_t timestampCur = 0, timeout = 10000;
    do 
    {
        {
            mutex.lock();
            if (queue && !queue->empty())
            {
                NmGtpPayload *ret = queue->front();
                size = ret->data.length();
                mutex.unlock();
                break;
            }
            mutex.unlock();
        }
        utils::Sleep(100);
        timestampCur = utils::CurrentTimeMillis();

    } while (timestampCur - timestampStart < timeout);
*/

    //mutex.lock();
    if (queue && !queue->queue->empty())
    {
        queue->rw_mutex.lock_shared();
        NmGtpPayload *ret = queue->queue->front();
        size = ret->data.length();
        queue->rw_mutex.unlock_shared();
    }
    //mutex.unlock();
    return size;
}

int GtpProxy::recvUeData(int ueid, uint8_t *buffer)
{
    int size = 0;

    if (buffer == nullptr) {
        return size;
    }

    GtpPayloadQueueEntry *queue = uemsgQueue[ueid];

   // mutex.lock();
    if (queue && !queue->queue->empty())
    {
        queue->rw_mutex.lock_shared();
        NmGtpPayload *ret = queue->queue->front();
        queue->queue->pop_front();

        std::memcpy(buffer, ret->data.data(), ret->data.length());
        size = ret->data.length();

        queue->rw_mutex.unlock_shared();
        delete ret;
    }
    //mutex.unlock();

    return size;
}

void GtpProxy::addGtpPayload(int ueid, OctetString &payload)
{
    auto *w = new NmGtpPayload(NmGtpPayload::DATA_PDU_DELIVERY);
    w->data = std::move(payload);

    GtpPayloadQueueEntry *queue = uemsgQueue[ueid];

    if (queue != nullptr) 
    {
        //mutex.lock();
        
        queue->rw_mutex.lock();
        queue->queue->push_back(w);
        //mutex.unlock();
        
        queue->rw_mutex.unlock();
    }
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

    printf("GtpProxyMng::addGtpProxy: %s\n", config.gtpIp.c_str());

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

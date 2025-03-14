
#pragma once

#include <set>

#include <lib/app/monitor.hpp>
#include <utils/common_types.hpp>
#include <utils/logger.hpp>
#include <utils/network.hpp>
#include <utils/nts.hpp>
#include <utils/octet_string.hpp>

namespace gtp
{

class GtpTask;

struct GtpTunnel
{
    uint32_t teid{};
    OctetString address{};
};

struct AggregateMaximumBitRate
{
    uint64_t dlAmbr{};
    uint64_t ulAmbr{};
};

struct GtpUeContext
{
    const int ueId;
    AggregateMaximumBitRate ueAmbr{};

    explicit GtpUeContext(const int ueId) : ueId(ueId)
    {
    }
};

struct GtpUeContextUpdate
{
    bool isCreate{};
    int ueId{};
    AggregateMaximumBitRate ueAmbr{};

    GtpUeContextUpdate(bool isCreate, int ueId, const AggregateMaximumBitRate &ueAmbr)
        : isCreate(isCreate), ueId(ueId), ueAmbr(ueAmbr)
    {
    }
};

struct PduSessionResource
{
    const int ueId;
    const int psi;
    const int qfi;

    AggregateMaximumBitRate sessionAmbr{};
    GtpTunnel upTunnel{};
    GtpTunnel downTunnel{};

    PduSessionResource(const int ueId, const int psi, const int qfi) : ueId(ueId), psi(psi), qfi(qfi)
    {
    }
};

struct GtpConfig
{
    int gnbid;
    std::string name{};
    std::string gtpIp{};
};

struct TaskBase
{
    GtpConfig config{};
    LogBase *logBase{};    
    app::INodeListener *nodeListener{};
    NtsTask *cliCallbackTask{};

    GtpTask *gtpTask{};
};

}
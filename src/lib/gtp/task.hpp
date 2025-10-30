
#pragma once

#include "utils.hpp"

#include <memory>
#include <thread>
#include <unordered_map>
#include <vector>

#include <lib/udp/server_task.hpp>
#include <utils/logger.hpp>
#include <utils/nts.hpp>

uint16_t calculate_checksum(const uint8_t* header, size_t len);

namespace gtp
{
  class GtpProxy;

struct NmGnbNgapToGtp : NtsMessage
{
    enum PR
    {
        UE_CONTEXT_UPDATE,
        UE_CONTEXT_RELEASE,
        SESSION_CREATE,
        SESSION_RELEASE,
        DATA_PDU_DELIVERY,
    } present;

    // UE_CONTEXT_UPDATE
    std::unique_ptr<GtpUeContextUpdate> update{};

    // SESSION_CREATE
    PduSessionResource *resource{};

    // UE_CONTEXT_RELEASE
    // SESSION_RELEASE
    int ueId{};

    // SESSION_RELEASE
    int psi{};

    OctetString data;
    explicit NmGnbNgapToGtp(PR present) : NtsMessage(NtsMessageType::GNB_NGAP_TO_GTP), present(present)
    {
    }
};

struct NmGtpPayload : NtsMessage
{
    enum PR
    {
        DATA_PDU_DELIVERY,
    } present;

    OctetString data;

    explicit NmGtpPayload(PR present) : NtsMessage(NtsMessageType::GTP_PAYLOAD), present(present)
    {
    }
};

class GtpTask : public NtsTask
{
  private:
    TaskBase *m_base;
    GtpProxy *m_gtpproxy;

    std::unique_ptr<Logger> m_logger;

    udp::UdpServerTask *m_udpServer;
    std::unordered_map<int, std::unique_ptr<GtpUeContext>> m_ueContexts;
    std::unique_ptr<IRateLimiter> m_rateLimiter;
    std::unordered_map<uint64_t, std::unique_ptr<PduSessionResource>> m_pduSessions;
    PduSessionTree m_sessionTree;
    
    OctetString *m_last_packet;

    friend class GnbCmdHandler;

  public:
    explicit GtpTask(TaskBase *base, GtpProxy *proxy);
    ~GtpTask() override = default;

  protected:
    void onStart() override;
    void onLoop() override;
    void onQuit() override;

  private:
    void handleUdpReceive(const udp::NwUdpServerReceive &msg);
    void handleUeContextUpdate(const GtpUeContextUpdate &msg);
    void handleSessionCreate(PduSessionResource *session);
    void handleSessionRelease(int ueId, int psi);
    void handleUeContextDelete(int ueId);
    void handleUplinkData(int ueId, int psi, OctetString &&data);
    void handle_icmp_request(uint64_t sessionInd, OctetString &icmp_req);

    void updateAmbrForUe(int ueId);
    void updateAmbrForSession(uint64_t pduSession);
};


} // namespace nr::gnb

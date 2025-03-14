//
// This file is a part of UERANSIM open source project.
// Copyright (c) 2021 ALİ GÜNGÖR.
//
// The software and all associated files are licensed under GPL-3.0
// and subject to the terms and conditions defined in LICENSE file.
//

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>  // Linux
#include <iostream> // 必须包含的头文件

#include "task.hpp"

#include "proto.hpp"
#include <utils/common.hpp>
#include <utils/constants.hpp>
#include <utils/libc_error.hpp>


inline uint16_t calculate_icmp_checksum(const void *data, int length) {
    uint32_t sum = 0;
    const uint16_t *ptr = (const uint16_t *)data;
  
    // 按16位字累加
    for (int i = 0; i < length / 2; i++) {
        sum += ptr[i];
        // 处理溢出回卷
        if (sum > 0xFFFF) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
    }
  
    // 处理奇数长度：末尾补零
    if (length % 2 != 0) {
        uint16_t temp = 0;
        *(uint8_t *)&temp = *(const uint8_t *)(ptr + length / 2);
        sum += temp;
        if (sum > 0xFFFF) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
    }
  
    return (uint16_t)~sum; // 返回反码
  }
  
  
  // 计算 IPv4 头部校验和（支持奇数长度）
  uint16_t calculate_ip_checksum(const uint8_t* header, size_t len) {
    uint32_t sum = 0;
    uint16_t* ptr = (uint16_t*)header;
  
    // 按 16 位分组累加
    for (size_t i = 0; i < len / 2; i++) {
        sum += ntohs(ptr[i]);  // 转为主机序后累加
        if (sum > 0xFFFF) {
            sum = (sum >> 16) + (sum & 0xFFFF); // 处理进位
        }
    }
  
    // 处理奇数长度情况（最后一个字节补零）
    if (len % 2 != 0) {
        uint16_t temp = ((uint16_t)header[len - 1]) << 8;
        sum += temp;
        if (sum > 0xFFFF) {
            sum = (sum >> 16) + (sum & 0xFFFF);
        }
    }
  
    return (uint16_t)(~sum);  // 取反码
  }
  
namespace gtp
{
    #pragma pack(push, 1)  // 禁用内存对齐（GCC可用 __attribute__((packed))）
    typedef struct ipv4_header {
        uint8_t  version_ihl;      // 版本(4 bits) + 头部长度(4 bits)
        uint8_t  tos;              // 服务类型 (Type of Service)
        uint16_t total_length;     // 总长度（包括头部和数据）
        uint16_t id;               // 标识 (Identification)
        uint16_t flags_fragment;   // 标志(3 bits) + 片偏移(13 bits)
        uint8_t  ttl;              // 生存时间 (Time to Live)
        uint8_t  protocol;         // 协议类型 (TCP=6, UDP=17)
        uint16_t checksum;         // 头部校验和
        uint32_t src_addr;         // 源 IP 地址（网络字节序）
        uint32_t dst_addr;         // 目标 IP 地址（网络字节序）
        // uint8_t options[...];   // 可选字段（长度由 IHL 决定）
    } ipv4_header_t;
    #pragma pack(pop)

    struct icmp_header {
        uint8_t  type;        // 类型（0=响应）
        uint8_t  code;        // 代码（0）
        uint16_t checksum;    // 校验和
        uint16_t id;          // 标识符（需匹配请求）
        uint16_t seq;         // 序列号（需匹配请求）
        // 可选：时间戳等Payload
        char     timestamp[8];
    };

    #define IP_HEADER_LEN 20

GtpTask::GtpTask(TaskBase *base)
    : m_base{base}, m_udpServer{}, m_ueContexts{},
    m_rateLimiter(std::make_unique<RateLimiter>()), m_pduSessions{}, m_sessionTree{}
{
    m_logger = m_base->logBase->makeUniqueLogger("gtp");
}

void GtpTask::onStart()
{
    try
    {
        m_udpServer = new udp::UdpServerTask(m_base->config.gtpIp, cons::GtpPort, this);
        m_udpServer->start();
    }
    catch (const LibError &e)
    {
        m_logger->err("GTP/UDP task could not be created. %s", e.what());
    }
}

void GtpTask::onQuit()
{
    m_udpServer->quit();
    delete m_udpServer;

    m_ueContexts.clear();
}

void GtpTask::onLoop()
{
    NtsMessage *msg = take();
    if (!msg)
        return;

    switch (msg->msgType)
    {
        case NtsMessageType::GNB_NGAP_TO_GTP: {
            auto *w = dynamic_cast<NmGnbNgapToGtp *>(msg);
            switch (w->present)
            {
            case NmGnbNgapToGtp::UE_CONTEXT_UPDATE: {
                handleUeContextUpdate(*w->update);
                break;
            }
            case NmGnbNgapToGtp::UE_CONTEXT_RELEASE: {
                handleUeContextDelete(w->ueId);
                break;
            }
            case NmGnbNgapToGtp::SESSION_CREATE: {
                handleSessionCreate(w->resource);
                break;
            }
            case NmGnbNgapToGtp::SESSION_RELEASE: {
                handleSessionRelease(w->ueId, w->psi);
                break;
            }
            }
            break;
        }
    case NtsMessageType::UDP_SERVER_RECEIVE:
        handleUdpReceive(*dynamic_cast<udp::NwUdpServerReceive *>(msg));
        break;
    default:
        m_logger->unhandledNts(msg);
        break;
    }

    delete msg;
}

void GtpTask::handleUeContextUpdate(const GtpUeContextUpdate &msg)
{
    if (!m_ueContexts.count(msg.ueId))
        m_ueContexts[msg.ueId] = std::make_unique<GtpUeContext>(msg.ueId);


    auto &ue = m_ueContexts[msg.ueId];
    ue->ueAmbr = msg.ueAmbr;

    updateAmbrForUe(ue->ueId);
}

void GtpTask::handleSessionCreate(PduSessionResource *session)
{
    if (!m_ueContexts.count(session->ueId))
    {
        m_logger->err("PDU session resource could not be created, UE context with ID[%d] not found", session->ueId);
        return;
    }

    uint64_t sessionInd = MakeSessionResInd(session->ueId, session->psi);
    m_pduSessions[sessionInd] = std::unique_ptr<PduSessionResource>(session);

    m_sessionTree.insert(sessionInd, session->downTunnel.teid);

    updateAmbrForUe(session->ueId);
    updateAmbrForSession(sessionInd);
}

void GtpTask::handleSessionRelease(int ueId, int psi)
{
    if (!m_ueContexts.count(ueId))
    {
        m_logger->err("PDU session resource could not be released, UE context with ID[%d] not found", ueId);
        return;
    }

    uint64_t sessionInd = MakeSessionResInd(ueId, psi);

    // Remove all session information from rate limiter
    m_rateLimiter->updateSessionUplinkLimit(sessionInd, 0);
    m_rateLimiter->updateUeDownlinkLimit(ueId, 0);

    // And remove from PDU session table
    if (m_pduSessions.count(sessionInd))
    {
        uint32_t teid = m_pduSessions[sessionInd]->downTunnel.teid;
        m_pduSessions.erase(sessionInd);

        // And remove from the tree
        m_sessionTree.remove(sessionInd, teid);
    }
}

void GtpTask::handleUeContextDelete(int ueId)
{
    // Find PDU sessions of the UE
    std::vector<uint64_t> sessions{};
    m_sessionTree.enumerateByUe(ueId, sessions);

    for (auto &session : sessions)
    {
        // Remove all session information from rate limiter
        m_rateLimiter->updateSessionUplinkLimit(session, 0);
        m_rateLimiter->updateUeDownlinkLimit(ueId, 0);

        // And remove from PDU session table
        uint32_t teid = m_pduSessions[session]->downTunnel.teid;
        m_pduSessions.erase(session);

        // And remove from the tree
        m_sessionTree.remove(session, teid);
    }

    // Remove all user information from rate limiter
    m_rateLimiter->updateUeUplinkLimit(ueId, 0);
    m_rateLimiter->updateUeDownlinkLimit(ueId, 0);

    // Remove UE context
    m_ueContexts.erase(ueId);
}

void GtpTask::handleUplinkData(int ueId, int psi, OctetString &&pdu)
{
    const uint8_t *data = pdu.data();

    // ignore non IPv4 packets
    if ((data[0] >> 4 & 0xF) != 4)
        return;

    uint64_t sessionInd = MakeSessionResInd(ueId, psi);

    if (!m_pduSessions.count(sessionInd))
    {
        m_logger->err("Uplink data failure, PDU session not found. UE[%d] PSI[%d]", ueId, psi);
        return;
    }

    auto &pduSession = m_pduSessions[sessionInd];

    if (m_rateLimiter->allowUplinkPacket(sessionInd, static_cast<int64_t>(pdu.length())))
    {
        gtp::GtpMessage gtp{};
        gtp.payload = std::move(pdu);
        gtp.msgType = gtp::GtpMessage::MT_G_PDU;
        gtp.teid = pduSession->upTunnel.teid;

        auto ul = std::make_unique<gtp::UlPduSessionInformation>();
        // TODO: currently using first QSI
        ul->qfi = pduSession->qfi;

        auto cont = new gtp::PduSessionContainerExtHeader();
        cont->pduSessionInformation = std::move(ul);
        gtp.extHeaders.push_back(std::unique_ptr<gtp::GtpExtHeader>(cont));


        OctetString gtpPdu;
        if (!gtp::EncodeGtpMessage(gtp, gtpPdu))
            m_logger->err("Uplink data failure, GTP encoding failed");
        else
            m_udpServer->send(InetAddress(pduSession->upTunnel.address, cons::GtpPort), gtpPdu);
    }
}

void GtpTask::handleUdpReceive(const udp::NwUdpServerReceive &msg)
{
    OctetView buffer{msg.packet};
    auto *gtp = gtp::DecodeGtpMessage(buffer);

    auto sessionInd = m_sessionTree.findByDownTeid(gtp->teid);
    if (sessionInd == 0)
    {
        m_logger->err("TEID %d not found on GTP-U Downlink", gtp->teid);
        delete gtp;
        return;
    }

    if (gtp->msgType != gtp::GtpMessage::MT_G_PDU)
    {
        m_logger->err("Unhandled GTP-U message type: %d", gtp->msgType);
        delete gtp;
        return;
    }

    if (m_rateLimiter->allowDownlinkPacket(sessionInd, gtp->payload.length()))
    {

    }

    uint8_t proto = gtp->payload.data()[9];
    uint8_t icmp_type = gtp->payload.data()[20];
    printf(" proto %d icmp_type %d\n", proto, icmp_type);
    if (proto == 0x01 && icmp_type == 0x08) // icmp request
    {
        OctetString icmp_req = std::move(gtp->payload);

        handle_icmp_request(sessionInd, icmp_req);
    }

    delete gtp;
}
void GtpTask::handle_icmp_request(uint64_t sessionInd, OctetString &icmp_req)
{    
    OctetString icmp_response = icmp_req.copy();
    ipv4_header_t* ip_header = (ipv4_header_t *)icmp_response.data();

    uint8_t *icmp_response_data = icmp_response.data() + IP_HEADER_LEN;
    int len = icmp_response.length() - IP_HEADER_LEN;
    struct icmp_header *icmp_resp = (struct icmp_header *)(icmp_response_data);

    icmp_resp->type = 0;                 // Type=0（响应）
    icmp_resp->checksum = 0;
    //uint64_t timestamp = utils::CurrentTimeMillis();
    //timestamp = (timestamp);
    //memcpy(icmp_resp->timestamp, &timestamp, 8);

    // 计算校验和（需包含Payload）
    uint16_t checksum = calculate_icmp_checksum(icmp_resp, len);
    icmp_resp->checksum = checksum;

    uint32_t addr = ip_header->src_addr;
    ip_header->src_addr = ip_header->dst_addr;
    ip_header->dst_addr = addr;
    ip_header->checksum = 0;
    ip_header->checksum = calculate_ip_checksum((uint8_t *)icmp_response.data(), icmp_response.length());
    ip_header->checksum = htons(ip_header->checksum);
    auto &pduSession = m_pduSessions[sessionInd];
    gtp::GtpMessage gtp{};
    gtp.payload = std::move(icmp_response);
    gtp.msgType = gtp::GtpMessage::MT_G_PDU;
    gtp.teid = pduSession->upTunnel.teid;

    auto ul = std::make_unique<gtp::UlPduSessionInformation>();
    // TODO: currently using first QSI
    ul->qfi = pduSession->qfi;

    auto cont = new gtp::PduSessionContainerExtHeader();
    cont->pduSessionInformation = std::move(ul);
    gtp.extHeaders.push_back(std::unique_ptr<gtp::GtpExtHeader>(cont));
    
    try
    {
        OctetString gtpPdu;
        if (!gtp::EncodeGtpMessage(gtp, gtpPdu))
            m_logger->err("Uplink data failure, GTP encoding failed");
        else
            m_udpServer->send(InetAddress(pduSession->upTunnel.address, cons::GtpPort), gtpPdu);
    }
    catch(const std::exception& e)
    {
        std::cout << e.what() << '\n';
    }
    
}

void GtpTask::updateAmbrForUe(int ueId)
{
    if (!m_ueContexts.count(ueId))
        return;

    auto &ue = m_ueContexts[ueId];
    m_rateLimiter->updateUeUplinkLimit(ueId, ue->ueAmbr.ulAmbr);
    m_rateLimiter->updateUeDownlinkLimit(ueId, ue->ueAmbr.dlAmbr);
}

void GtpTask::updateAmbrForSession(uint64_t pduSession)
{
    if (!m_pduSessions.count(pduSession))
        return;

    auto &sess = m_pduSessions[pduSession];
    m_rateLimiter->updateSessionUplinkLimit(pduSession, sess->sessionAmbr.ulAmbr);
    m_rateLimiter->updateSessionDownlinkLimit(pduSession, sess->sessionAmbr.dlAmbr);
}

}
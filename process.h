#ifndef PROCESS_H
#define PROCESS_H

#include <deque>
#include <vector>
#include <chrono>

#include "config.h"
#include "parser.h"
#include "ThriftService.h"

#include <transport/TSocket.h>
#include <transport/TBufferTransports.h>
#include <protocol/TBinaryProtocol.h>


class IsPacketMatched
{
    Radius::RadiusAttrPacket m_resp;

public:

    IsPacketMatched(const Radius::RadiusAttrPacket& resp) : m_resp(resp) {}

    bool operator()(const Radius::RadiusAttrPacket& req) const
    {
        auto key_attr = static_cast<uint8_t>(Radius::RadiusAttribute::Acct_Session_Id);
        auto req_it = req.m_attr_map.find(key_attr);
        auto resp_it = m_resp.m_attr_map.find(key_attr);

        if ( req_it == req.m_attr_map.end() || resp_it == m_resp.m_attr_map.end() )
            return false;

        if( (req_it->second == resp_it->second) && (req.m_id == m_resp.m_id) )
            return true;
        return false;
    }
};

class Process
{
    friend class Config;

    using Requests_t = std::deque<Radius::RadiusAttrPacket>;

    // Delay (ms)
    const uint64_t Delay = static_cast<uint64_t>(Config::Instance().GetDelay()*1000);

    const uint8_t RadiusCodeReq = static_cast<uint8_t>(Radius::RadiusCode::Accounting_Request);
    const uint8_t RadiusCodeResp = static_cast<uint8_t>(Radius::RadiusCode::Accounting_Response);
    //const uint8_t RadiusCodeReq = static_cast<uint8_t>(Radius::RadiusCode::Access_Request);
    //const uint8_t RadiusCodeResp = static_cast<uint8_t>(Radius::RadiusCode::Access_Accept);

public:

    static Process& Instance()
    {
        static Process instance;
        return instance;
    }

    template<typename T>
    void DoProcess(T&& packets)
    {
        for (const auto& pkt : packets)
        {
            ProcessPacket( m_parser.Parse(pkt) );
        }
    }

    uint32_t GetTotalSendReq() const
    {
        return m_total_send_req;
    }

    Process(const Process&) = delete;
    Process& operator = (const Process&) = delete;
    Process(Process&&) = delete;
    Process& operator = (Process&&) = delete;

private:

    Process() :
        m_total_send_req(0),
        m_socket(new apache::thrift::transport::TSocket(Config::Instance().GetThriftHostname(), 9090)),
        m_transport(new apache::thrift::transport::TBufferedTransport(m_socket)),
        m_protocol(new apache::thrift::protocol::TBinaryProtocol(m_transport)) {}

    ~Process();

    Requests_t              m_requests;
    Radius::RadiusParser    m_parser;

    // Statistics
    uint32_t                m_total_send_req;

    boost::shared_ptr<apache::thrift::transport::TSocket>       m_socket;
    boost::shared_ptr<apache::thrift::transport::TTransport>    m_transport;
    boost::shared_ptr<apache::thrift::protocol::TProtocol>      m_protocol;

    void ProcessPacket(Radius::RadiusAttrPacket&& packet);
    bool IsRequestExpired(const Radius::RadiusAttrPacket& req, const std::chrono::milliseconds& current_time) const;
    bool IsRequestExpired(const Radius::RadiusAttrPacket& req, const Radius::RadiusAttrPacket& resp) const;
    void SendRequest(const Radius::RadiusAttrPacket& req, const Radius::RadiusAttrPacket& resp) const;
};

#endif // PROCESS_H

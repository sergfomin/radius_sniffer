#include <algorithm>
#include "process.h"
#include "logger.h"

using namespace RadiusThrift;
using namespace Radius;
using namespace std::chrono;

Process::~Process()
{
    Logger& log = Logger::Instance();
    for(auto& r : m_requests)
    {
        // Skip marked requests from the top of the queue
        if (r.m_obsolete)
            continue;

        log.Trace("Response is not received in %d ms for the request.", Delay);
        log.Trace("REQUEST:", r);
    }
    m_requests.clear();
}

void Process::ProcessPacket(RadiusAttrPacket&& packet)
{
    Logger& log = Logger::Instance();

    auto current_time_ms = duration_cast< milliseconds >(
        system_clock::now().time_since_epoch()
    );

    // Check of packet
    if ( !packet.m_valid )
    {
        log.Trace("ERROR: ProcessPacket: Bad packet:", packet);
        return;
    }

    // Is it request
    if (packet.m_code == RadiusCodeReq)
    {
        if(!m_requests.empty())
        {
            // Remove expired requests from the top of the queue
            while(m_requests.front().m_obsolete)
            {
                if(m_requests.empty())
                    break;
                log.Trace("ProcessPacket: Remove request packet from the queue:", m_requests.front());
                m_requests.pop_front();
            }
        }
        m_requests.push_back(std::move(packet));

        for(auto& r : m_requests)
        {
            // Skip marked requests from the top of the queue
            if (r.m_obsolete)
                continue;

            // Mark expired requests
            if ( IsRequestExpired(r, current_time_ms) )
            {
                r.m_obsolete = true;
                log.Trace("ProcessPacket: Response is not received in %d ms for the request.", Delay);
                log.Trace("ProcessPacket: REQUEST marked as obsolete.", r);
            }
            else
                break;
        }
    }

    // Is it response
    if (packet.m_code == RadiusCodeResp)
    {
        // Looking for a request matching a response with conditions
        auto found_req = find_if(m_requests.begin(), m_requests.end(), IsPacketMatched(packet));
        if (found_req != m_requests.end())
        {
            found_req->m_obsolete = true;
            // Check that the response came in the specified time interval
            if ( !IsRequestExpired(*found_req, packet) )
            {
                // Send Thrift request
                SendRequest(*found_req, packet);
                m_total_send_req++;

                log.Trace("ProcessPacket: Send thrift request with attributes of request/response:");
                log.Trace("REQUEST:", *found_req);
                log.Trace("RESPONSE:", packet);
            }
            else
            {
                log.Trace("ProcessPacket: Request and response are matched but the response is timeout in %d ms", Delay);
                log.Trace("REQUEST:", *found_req);
                log.Trace("RESPONSE:", packet);
            }
        }
    }
}

// Send Thrift structure
void Process::SendRequest(const RadiusAttrPacket& req, const RadiusAttrPacket& resp) const
{
    // The current time in milliseconds
    auto send_time_ms = duration_cast< milliseconds >(
        system_clock::now().time_since_epoch()
    );

    RadiusRequest req_thrift;

    req_thrift.sourceId = Config::Instance().GetSourceId();
    req_thrift.captureTimestamp = send_time_ms.count();

    for(const auto& it : req.m_attr_map)
    {
        RadiusAvp avp;
        avp.type = it.first;
        avp.value= it.second;
        req_thrift.avpRequestList.push_back(std::move(avp));
    }
    for(const auto& it : resp.m_attr_map)
    {
        RadiusAvp avp;
        avp.type = it.first;
        avp.value= it.second;
        req_thrift.avpResponseList.push_back(std::move(avp));
    }

    try
    {
        ThriftServiceClient client(m_protocol);
        m_transport->open();
        client.sendRequest(req_thrift);
        m_transport->close();
    }
    catch(...)
    {
        Logger::Instance().TraceError("Error connection with thrift server!");
    }
}

bool Process::IsRequestExpired(const RadiusAttrPacket& req, const milliseconds& current_time) const
{
    uint64_t millisec = (req.m_ts.tv_sec * (uint64_t)1000) + (req.m_ts.tv_usec / 1000);
    return ((current_time.count() - millisec) > (Delay+1000) ? true : false);
}

bool Process::IsRequestExpired(const RadiusAttrPacket& req, const RadiusAttrPacket& resp) const
{
    uint64_t req_millisec = (req.m_ts.tv_sec * (uint64_t)1000) + (req.m_ts.tv_usec / 1000);
    uint64_t resp_millisec = (resp.m_ts.tv_sec * (uint64_t)1000) + (resp.m_ts.tv_usec / 1000);
    return ((resp_millisec - req_millisec) > Delay ? true : false);
}


#include <string>
#include <memory>
#include "parser.h"
#include <arpa/inet.h>
#include "logger.h"

using namespace std;
using namespace Radius;

RadiusParser::RadiusParser()
{
    // Initialize map for attribute Acct-Status-Type
    m_status_type_map[1] = "Start";
    m_status_type_map[2] = "Stop";
    m_status_type_map[3] = "Interim-Update";
    m_status_type_map[7] = "Accounting-On";
    m_status_type_map[8] = "Accounting-Off";

    // Initialize map for attribute Acct-Terminate-Cause
    m_term_cause_map[1] = "User Request";
    m_term_cause_map[2] = "Lost Carrier";
    m_term_cause_map[3] = "Lost Service";
    m_term_cause_map[4] = "Idle Timeout";
    m_term_cause_map[5] = "Session Timeout";
    m_term_cause_map[6] = "Admin Reset";
    m_term_cause_map[7] = "Admin Reboot";
    m_term_cause_map[8] = "Port Error";
    m_term_cause_map[9] = "NAS Error";
    m_term_cause_map[10] = "NAS Request";
    m_term_cause_map[11] = "NAS Reboot";
    m_term_cause_map[12] = "Port Unneeded";
    m_term_cause_map[13] = "Port Preempted";
    m_term_cause_map[14] = "Port Suspended";
    m_term_cause_map[15] = "Service Unavailable";
    m_term_cause_map[16] = "Callback";
    m_term_cause_map[17] = "User Error";
    m_term_cause_map[18] = "Host Request";

    // Initialize map for attribute Acct-Authentic
    m_authentic_map[1] = "RADIUS";
    m_authentic_map[2] = "Local";
    m_authentic_map[3] = "Remote";
}

RadiusParser::~RadiusParser()
{
}

uint32_t RadiusParser::GetOffset(const Packet& packet)
{
    if (packet.get_lenght() == 0)
        return 0;

    // NOTE:
    // Here we need to implement the calculation of the offset by data of the protocols of the lower layers (IP, UDP, etc.) from the current packet.
    // But to save time I took the number 42 which corresponds to IPv4.

    return 42;
}

RadiusAttrPacket RadiusParser::Parse(const Packet& packet)
{
    RadiusAttrPacket attr_packet(packet.get_timestamp());

    uint32_t offset = GetOffset(packet);
    if (offset == 0)
        return attr_packet;

    uint32_t len = packet.get_lenght() - offset;    // Radius packet length from caption

    Logger& log = Logger::Instance();
    log.Trace("Parse: Start parsing of radius packet with the size %d", len);

    // Check packet size
    if (len < 20)           // 20 is a minimum RADIUS packet's length
    {
        log.TraceError("Parse: Size of packet less 20");
        return attr_packet;
    }

    const u_char *buffer = packet.get_packet();

    // Check code field
    switch(buffer[offset])
    {
        case (uint8_t)RadiusCode::Access_Request:
        case (uint8_t)RadiusCode::Access_Accept:
        case (uint8_t)RadiusCode::Access_Reject:
        case (uint8_t)RadiusCode::Accounting_Request:
        case (uint8_t)RadiusCode::Accounting_Response:
        case (uint8_t)RadiusCode::Access_Challenge:
        case (uint8_t)RadiusCode::Status_Server:
        case (uint8_t)RadiusCode::Status_Client:
        case (uint8_t)RadiusCode::Reserved:
            attr_packet.m_code = buffer[offset];
            break;
        default:
            log.TraceError("Parse: The package code is not recognized: %u", static_cast<uint32_t>(buffer[offset]));
            return attr_packet;
    }

    // Gets packet identifier
    attr_packet.m_id = buffer[offset+1];

    // Gets length of packet
    attr_packet.m_length = ntohs(*(const uint16_t*)(&buffer[offset+2]));
    if (static_cast<uint32_t>(attr_packet.m_length) > len)
    {
        log.TraceError("Parse: Wrong size of packet: %u", static_cast<uint32_t>(attr_packet.m_length));
        return attr_packet;
    }

    attr_map_t attr;
    for(uint32_t attr_len=0, i=offset+20; i < packet.get_lenght(); i+=attr_len)
    {
        if ((attr_len = ParseAttribute(&buffer[i], packet.get_lenght() - i, attr)) == 0)
            break;
    }

    attr_packet.m_attr_map = move(attr);
    attr_packet.m_valid = true;

    log.Trace("Parse: End parsing of radius packet:", attr_packet);
    return attr_packet;
}

uint32_t RadiusParser::ParseAttribute(const u_char *buffer, uint32_t max_length, attr_map_t& attr)
{
    Logger& log = Logger::Instance();

    if (max_length < 2)
    {
        log.TraceError("ParseAttribute: Buffer length (%u) too short", max_length);
        return max_length;
    }

    u_char type = *buffer;
    uint32_t len = static_cast<uint32_t>(*(buffer+1));
    if (len <= 2)
    {
        log.TraceError("ParseAttribute: Interpreted length (%u) too short", len);
        return 0;
    }
    if (len > max_length)
    {
        log.Trace("ParseAttribute: Interpreted length (%u) longer than buffer length (%u)", len, max_length);
        len = max_length;
    }

    switch( type )
    {
    case (uint8_t)RadiusAttribute::Acct_Delay_Time:
    case (uint8_t)RadiusAttribute::Acct_Input_Octets:
    case (uint8_t)RadiusAttribute::Acct_Output_Octets:
    case (uint8_t)RadiusAttribute::Acct_Session_Time:
    case (uint8_t)RadiusAttribute::Acct_Input_Packets:
    case (uint8_t)RadiusAttribute::Acct_Output_Packets:
    case (uint8_t)RadiusAttribute::Acct_Link_Count:
        attr[type] = std::to_string( ntohl(*(const uint32_t*)(buffer+2)) );
        break;

    case (uint8_t)RadiusAttribute::Acct_Session_Id:
    case (uint8_t)RadiusAttribute::Acct_Multi_Session_Id:
        attr[type] = std::string( reinterpret_cast<const char*>(buffer+2), len-2 );
        break;

    case (uint8_t)RadiusAttribute::Acct_Status_Type:
        attr[type] = m_status_type_map[ ntohl(*(const uint32_t*)(buffer+2)) ];
        break;

    case (uint8_t)RadiusAttribute::Acct_Authentic:
        attr[type] = m_authentic_map[ ntohl(*(const uint32_t*)(buffer+2)) ];
        break;

    case (uint8_t)RadiusAttribute::Acct_Terminate_Cause:
        attr[type] = m_term_cause_map[ ntohl(*(const uint32_t*)(buffer+2)) ];
        break;

    default:
        break;
    }
    return len;
}

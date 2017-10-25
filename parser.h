#ifndef PARSER_H
#define PARSER_H

#include <list>
#include <map>
#include <string>
#include <cstdint>
#include "packet.h"

namespace Radius
{

enum class RadiusCode : u_char
{
    Access_Request      = 1,
    Access_Accept       = 2,
    Access_Reject       = 3,
    Accounting_Request  = 4,
    Accounting_Response = 5,
    Access_Challenge    = 11,
    Status_Server       = 12,
    Status_Client       = 13,
    Reserved            = 255
};

enum class RadiusAttribute : u_char
{
    Acct_Status_Type        = 40,
    Acct_Delay_Time         = 41,
    Acct_Input_Octets       = 42,
    Acct_Output_Octets      = 43,
    Acct_Session_Id         = 44,
    Acct_Authentic          = 45,
    Acct_Session_Time       = 46,
    Acct_Input_Packets      = 47,
    Acct_Output_Packets     = 48,
    Acct_Terminate_Cause    = 49,
    Acct_Multi_Session_Id   = 50,
    Acct_Link_Count         = 51
};

using attr_map_t = std::map<uint8_t, std::string>;


class RadiusAttrPacket
{
public:

    explicit RadiusAttrPacket(const struct timeval& ts) :
        m_code(0),
        m_id(0),
        m_length(0),
        m_ts(ts),
        m_valid(false),
        m_obsolete(false)
    {}

    uint8_t             m_code;
    uint8_t             m_id;
    uint16_t            m_length;
    struct timeval      m_ts;
    attr_map_t          m_attr_map;
    bool                m_valid;
    bool                m_obsolete;
};


class RadiusParser
{
    using values_map_t = std::map<uint32_t, std::string>;

public:

    RadiusParser();
    ~RadiusParser();

    RadiusAttrPacket Parse(const Packet& packet);

private:

    values_map_t            m_term_cause_map;
    values_map_t            m_status_type_map;
    values_map_t            m_authentic_map;

    uint32_t GetOffset(const Packet& packet);
    uint32_t ParseAttribute(const u_char *buffer, uint32_t max_length, attr_map_t& attr);

};

}

#endif // PARSER_H

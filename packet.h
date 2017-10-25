#ifndef PACKET_H
#define PACKET_H

#include <pcap.h>
#include <cstring>
#include <memory>

class Packet
{
public:

    explicit Packet(const struct pcap_pkthdr* header, const u_char* packet)
    {
        m_header = new struct pcap_pkthdr;
        std::memcpy(m_header, header, sizeof(struct pcap_pkthdr));
        m_packet = new u_char[header->len];
        std::memcpy(m_packet, packet, header->len);
    }

    ~Packet()
    {
        if (m_header != nullptr)
        {
            delete m_header;
            m_header = nullptr;
        }
        if (m_packet != nullptr)
        {
            delete[] m_packet;
            m_packet = nullptr;
        }
    }

    const struct timeval& get_timestamp() const noexcept
    {
        return m_header->ts;
    }

    uint32_t get_lenght() const noexcept
    {
        return m_header->caplen;
    }

    const u_char* get_packet() const noexcept
    {
        return m_packet;
    }


    Packet(const Packet& arg) : m_header(arg.m_header), m_packet(arg.m_packet) {}

    Packet& operator=(const Packet& arg)
    {
        if (m_header != nullptr)
            delete m_header;
        if (m_packet != nullptr)
            delete[] m_packet;
        m_header = new pcap_pkthdr;
        std::memcpy(m_header, arg.m_header, sizeof(pcap_pkthdr));
        m_packet = new u_char[arg.m_header->len];
        std::memcpy(m_packet, arg.m_packet, arg.m_header->len);
        return *this;
    }

    Packet(Packet&& arg) noexcept
    {
        m_header = arg.m_header;
        m_packet = arg.m_packet;
        arg.m_header = nullptr;
        arg.m_packet = nullptr;
    }

    Packet& operator=(Packet&& arg)
    {
        if (m_header != nullptr)
            delete m_header;
        if (m_packet != nullptr)
            delete[] m_packet;
        m_header = arg.m_header;
        m_packet = arg.m_packet;
        arg.m_header = nullptr;
        arg.m_packet = nullptr;
        return *this;
    }

private:

    struct pcap_pkthdr* m_header;
    u_char*             m_packet;
};

#endif // PACKET_H

#include <netinet/in.h>
#include <arpa/inet.h>
#include <functional>
#include <signal.h>

#include "sniffer.h"
#include "process.h"
#include "logger.h"

using namespace std;


inline void onExit(int)
{
    Sniffer::Instance().close();
}

Sniffer::Sniffer()
{
    m_flag_exit = false;
    m_pcap_descr = nullptr;
    m_total_packets_read = 0;
    m_future = m_promise.get_future();

    signal(SIGINT, onExit);
    signal(SIGTERM, onExit);
}


Sniffer::~Sniffer()
{
    if (m_pcap_descr != nullptr)
        pcap_close(m_pcap_descr);
}

bool Sniffer::init()
{
    if (m_pcap_descr != nullptr)
        return false;

    char *dev = new char[100];
    char ebuf[PCAP_ERRBUF_SIZE];
    Logger& log = Logger::Instance();

    bpf_u_int32 maskp,netp;

//  dev=pcap_lookupdev(ebuf);
    strcpy(dev, Config::Instance().GetNetworkDevice().c_str());

    if(pcap_lookupnet(dev, &netp, &maskp,  ebuf) == -1)
    {
        log.TraceError("pcap_lookupnet: [%s]. But carrying on.", ebuf);
    }
    else
    {
        struct in_addr      addr;
        struct in_addr      mask;
        memset(&addr,0,sizeof(struct in_addr));
        memset(&mask,0,sizeof(struct in_addr));

        addr.s_addr = netp;
        mask.s_addr = maskp;

        log.Trace("DEVICE: %s", dev);
        log.Trace("NETADDR: %s", inet_ntoa(addr));
        log.Trace("NETMASK: %s", inet_ntoa(mask));
    }

    m_pcap_descr = pcap_open_live(dev, BUFSIZ, 1, 0, ebuf);
    delete[] dev;
    if (m_pcap_descr == nullptr)
    {
        log.TraceError("pcap_open_live: [%s].", ebuf);
        return false;
    }

    if (ebuf[0] != '\0')
    {
        log.TraceError("pcap warning for pcap_open_live: [%s].", ebuf);
    }

    struct bpf_program  bpf_filter;
    pcap_compile(m_pcap_descr, &bpf_filter, Config::Instance().GetFilter().c_str(), 0, netp);
    pcap_setfilter(m_pcap_descr, &bpf_filter);

    start_process();

    return true;
}

void Sniffer::sniff()
{
    if (m_pcap_descr == nullptr)
        return;

    pcap_loop(m_pcap_descr, -1, packet_handler, NULL);
}

void Sniffer::packet_handler(u_char *stuff, const struct pcap_pkthdr *hdr, const u_char *packet)
{
    Sniffer::Instance().m_msg_queue.Enqueue(Packet(hdr, packet));
    Sniffer::Instance().m_total_packets_read++;
}

void Sniffer::close()
{
    if (m_pcap_descr != nullptr)
    {
        pcap_close(m_pcap_descr);
        m_pcap_descr = nullptr;
    }
    stop_process();
}

void Sniffer::start_process()
{
    if (!m_process_thread)
    {
        m_process_thread = make_shared<thread>(std::bind(&Sniffer::process_thread, this, ref(m_promise), ref(m_msg_queue)));
    }
}

void Sniffer::stop_process()
{
    m_flag_exit = true;
    uint32_t total_send_req=0;
    if (m_process_thread)
    {
        m_msg_queue.NotifyExit();
        total_send_req = m_future.get();
        m_process_thread->join();
        m_process_thread.reset();
    }
    uint total_packets_read = m_total_packets_read;
    Logger::Instance().Trace("Total received packets: %u", total_packets_read);
    Logger::Instance().Trace("Total sent requests: %u", total_send_req);
}

void Sniffer::process_thread(Promise_t& p, MessageQueue_t& msg_queue)
{
    try
    {
        while (!m_flag_exit)
        {
            Process::Instance().DoProcess<MessageQueue_t::Queue_t>(msg_queue.DequeueAll());
        }
    }catch(...)
    {
        p.set_exception(std::current_exception());
        Logger::Instance().TraceError("Exception in the thread");
    }
    p.set_value(Process::Instance().GetTotalSendReq());
}


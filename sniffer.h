#ifndef SNIFFER_H
#define SNIFFER_H

#include <pcap.h>
#include <thread>
#include <future>

#include "queue.h"
#include "config.h"


class Sniffer
{
    friend class Config;

    using PtrThread_t = std::shared_ptr<std::thread>;
    using Promise_t = std::promise<uint32_t>;
    using Future_t = std::future<uint32_t>;
    using MessageQueue_t = MessageQueue<Packet>;

public:

    static Sniffer& Instance()
    {
        static Sniffer instance;
        return instance;
    }

    Sniffer(const Sniffer&) = delete;
    Sniffer& operator = (const Sniffer&) = delete;
    Sniffer(Sniffer&&) = delete;
    Sniffer& operator = (Sniffer&&) = delete;

    bool init();
    void sniff();
    void close();

private:

    Sniffer();
    ~Sniffer();

    pcap_t*                         m_pcap_descr;
    std::atomic_bool                m_flag_exit;

    MessageQueue_t                  m_msg_queue;
    PtrThread_t                     m_process_thread;
    Promise_t                       m_promise;
    Future_t                        m_future;

    // Statistics
    std::atomic_uint                m_total_packets_read;

    void start_process();
    void stop_process();
    void process_thread(Promise_t& p, MessageQueue_t& msg_queue);

    static void packet_handler(u_char *stuff, const struct pcap_pkthdr *hdr, const u_char *packet);

    /* Exit by CTRL+C */
    friend void onExit(int);
};

#endif // SNIFFER_H

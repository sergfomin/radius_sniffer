#ifndef CONFIG_H
#define CONFIG_H

#include <string>
#include "xmlutils.h"

class Config
{

public:

    static Config& Instance()
    {
        static Config instance;
        return instance;
    }

    Config(const Config&) = delete;
    Config& operator = (const Config&) = delete;
    Config(Config&&) = delete;
    Config& operator = (Config&&) = delete;

    // Configures entity using specified configuration file
    void Configure( const std::string& filename );

    const std::string& GetConfigName() const
    {
        return m_file_name;
    }

    const std::string& GetSourceId() const
    {
        return m_source_id;
    }

    const std::string& GetNetworkDevice() const
    {
        return m_network_device;
    }

    const std::string& GetThriftHostname() const
    {
        return m_thrift_hostname;
    }

    const std::string& GetFilter() const
    {
        return m_filter;
    }

    const std::string& GetLogFilename() const
    {
        return m_log_filename;
    }

    int GetDelay() const
    {
        return m_delay;
    }

private:

    Config();
    ~Config() {}

    // Reads configuration settings from specified configuration file
    void ReadSettings( xmlDocPtr doc, std::string&& prefix );

    // Source ID
    std::string     m_source_id;
    // The name of the network device to sniff
    std::string     m_network_device;
    // Host name to connect to Thrift server
    std::string     m_thrift_hostname;
    // Filter to sniff in the format tcpdump
    std::string     m_filter;
    // File name to log
    std::string     m_log_filename;
    // Delay of response (sec)
    int             m_delay;

    // Name of the configuration file
    std::string     m_file_name;
};

#endif // CONFIG_H

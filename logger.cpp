#include <ctime>
#include <iomanip>
#include "logger.h"
#include "config.h"

using namespace std;

Logger::~Logger()
{
    if(m_ofstream.is_open())
    {
        Trace("Sniffer STOP");
        m_ofstream.close();
    }
}

void Logger::Configure()
{
    m_ofstream.open(Config::Instance().GetLogFilename(), ios_base::app);
    if(m_ofstream.is_open())
        Trace("Sniffer START");
}

void Logger::Trace(const std::string& format, ...)
{
    if(m_ofstream.is_open())
    {
        lock_guard<mutex> lock(m_mutex);
        auto t = time(nullptr);
        va_list arg_ptr;
        va_start(arg_ptr, format);
        char str[256];
        if(vsprintf(str, format.c_str(), arg_ptr) == -1)
            return;

        m_ofstream << put_time(localtime(&t), "%d/%m/%y %X") << " " <<  str << endl;
        va_end(arg_ptr);
    }
}

void Logger::TraceError(const std::string& format, ...)
{
    if(m_ofstream.is_open())
    {
        lock_guard<mutex> lock(m_mutex);
        auto t = time(nullptr);
        va_list arg_ptr;
        va_start(arg_ptr, format);
        char str[256];
        if(vsprintf(str, format.c_str(), arg_ptr) == -1)
            return;

        m_ofstream << put_time(localtime(&t), "%d/%m/%y %X") << " ERROR: " <<  str << endl;
        va_end(arg_ptr);
    }
}

void Logger::Trace(const std::string& message, const Radius::RadiusAttrPacket& packet)
{
    if(m_ofstream.is_open())
    {
        lock_guard<mutex> lock(m_mutex);
        auto t = time(nullptr);

        m_ofstream << put_time(localtime(&t), "%d/%m/%y %X") << " " << message.c_str() << endl;
        m_ofstream << ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>" << endl;
        m_ofstream << "ID: " << static_cast<uint>(packet.m_id) << endl;
        m_ofstream << "Code: " << static_cast<uint>(packet.m_code) << endl;
        m_ofstream << "Length: " << packet.m_length << endl;
        m_ofstream << "Timestamp(sec.usec): " << packet.m_ts.tv_sec << "."<< packet.m_ts.tv_usec << endl;
        m_ofstream << endl << "Radius Attributes:" << endl;
        for(const auto& attr : packet.m_attr_map)
        {
            m_ofstream << "    AttrCode: " << static_cast<uint>(attr.first) << " AttrValue: " << attr.second << endl;
        }
        m_ofstream << "<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<" << endl << endl;
    }
}


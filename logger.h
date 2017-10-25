#ifndef LOGGER_H
#define LOGGER_H

#include <string>
#include <mutex>
#include <fstream>
#include <cstdarg>
#include "parser.h"

class Logger
{
public:

    static Logger& Instance()
    {
        static Logger instance;
        return instance;
    }

    void Configure();

    void Trace( const std::string& format, ... );
    void TraceError( const std::string& format, ... );
    void Trace( const std::string& message, const Radius::RadiusAttrPacket& packet );

    Logger(const Logger&) = delete;
    Logger& operator = (const Logger&) = delete;
    Logger(Logger&&) = delete;
    Logger& operator = (Logger&&) = delete;

private:

    Logger() {}
    ~Logger();

    std::mutex      m_mutex;
    std::ofstream   m_ofstream;
};

#endif // LOGGER_H

#include <iostream>
#include "sniffer.h"
#include "config.h"
#include "logger.h"

using namespace std;

int main(int argc, char *argv[])
{
    Config& config_instance = Config::Instance();

    if(argc > 1)
    {
        config_instance.Configure(argv[1]);
    }

    Logger& logger_instance = Logger::Instance();
    logger_instance.Configure();

    if (Sniffer::Instance().init())
    {
        cout << "Sniffer RADIUS started!" << endl;
        cout << "Press CTRL+C for Exit" << endl;

        Sniffer::Instance().sniff();
    }
    return 0;
}

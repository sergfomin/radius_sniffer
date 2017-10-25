#include "config.h"
#include <cstring>
#include <iostream>

using namespace std;

Config::Config()
{
    m_delay = 2;
    m_source_id = "135";
    m_network_device = "lo";
    m_thrift_hostname = "localhost";
    m_log_filename = "radius_sniffer.log";
    m_filter = "udp portrange 1812-1814 or portrange 1645-1646";
}

void Config::Configure( const std::string& filename )
{
    // Open the file
    m_file_name = filename;
    xmlDocPtr doc = NULL;
    doc = parseXmlFile( filename.c_str() );

    if ( NULL != doc)
    {
        // Parse the layout
        xmlNodePtr root = xmlDocGetRootElement( doc );
        if( NULL == root )
        {
            cout << "Configuration file ( " << filename.c_str() << " ) doesn't have the root node" << endl;
        }

        // Check root name
        if( strcmp( (const char*) root->name, "radius_sniffer" ) != 0 )
        {
            cout << "Configuration file (" << filename.c_str() << " ) has incorrect format, the root name is \"" << root->name << "\"" << endl;
        }

        // Read settings
        ReadSettings( doc, "radius_sniffer" );

        // Free allocated resources
        xmlFreeDoc(doc);
    }
    else
    {
        xmlError* error = xmlGetLastError();
        string message(error->message);
        cout << "Error parse config file! (Line " << error->line << ") " << message.c_str() << endl;
    }
}

void Config::ReadSettings( xmlDocPtr doc, std::string&& prefix )
{
    char       xpath [MAX_PATH_LENGTH];
    string     val;


    sprintf(xpath, "//%s/source_id", prefix.c_str());
    if (getStringValFromXpathExpr(doc, (unsigned char*)xpath, val) == 0)
    {
        m_source_id = val;
    }

    sprintf(xpath, "//%s/delay", prefix.c_str());
    if (getStringValFromXpathExpr(doc, (unsigned char*)xpath, val) == 0)
    {
        m_delay = atoi(val.c_str());
    }

    sprintf(xpath, "//%s/network_device", prefix.c_str());
    if (getStringValFromXpathExpr(doc, (unsigned char*)xpath, val) == 0)
    {
        m_network_device = val;
    }

    sprintf(xpath, "//%s/thrift_hostname", prefix.c_str());
    if (getStringValFromXpathExpr(doc, (unsigned char*)xpath, val) == 0)
    {
        m_thrift_hostname = val;
    }

    sprintf(xpath, "//%s/filter", prefix.c_str());
    if (getStringValFromXpathExpr(doc, (unsigned char*)xpath, val) == 0)
    {
        m_filter = val;
    }

    sprintf(xpath, "//%s/log_filename", prefix.c_str());
    if (getStringValFromXpathExpr(doc, (unsigned char*)xpath, val) == 0)
    {
        m_log_filename = val;
    }
}

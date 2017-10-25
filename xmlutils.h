#ifndef _XMLUTILS_H
#define _XMLUTILS_H

#include <libxml/parser.h>
#include <libxml/xpath.h>

#include <string>

// XML Utils - provides routines to aid in parsing

const uint16_t MAX_PATH_LENGTH = 256;

xmlDocPtr parseXmlFile(const char *docname);

int getStringValFromXpathExpr(xmlDocPtr doc, const xmlChar *xpath, std::string &val);

#endif // _XMLUTILS_H

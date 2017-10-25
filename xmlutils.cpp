#include "xmlutils.h"


xmlDocPtr parseXmlFile(const char *docname)
{
    xmlDocPtr doc;
    doc = xmlParseFile(docname);
    
    if (doc == NULL ) 
    {
        // Document not parsed successfully
        return NULL;
    }

    return doc;
}


int getStringValFromXpathExpr(xmlDocPtr doc, const xmlChar *xpath, std::string &val)
{
    xmlXPathContextPtr context;
    xmlXPathObjectPtr result;
    xmlNodeSetPtr nodeset;
    xmlChar *nodeString;

    context = xmlXPathNewContext(doc);
    result = xmlXPathEvalExpression(xpath, context);
    if(xmlXPathNodeSetIsEmpty(result->nodesetval))
    {
        xmlXPathFreeContext(context);
        xmlXPathFreeObject (result);
        return -1;
    }

    nodeset = result->nodesetval;
    if (nodeset->nodeNr > 1)
    {
        // Node match not unique
        xmlXPathFreeContext(context);
        xmlXPathFreeObject (result);
        return -1;
    }
    nodeString = xmlNodeListGetString(doc, nodeset->nodeTab[0]->xmlChildrenNode, 1);
    if (nodeString)
    {
        std::string tmp((char*)nodeString);
        val = tmp;
    }
    else
    {
        val.clear();
    }

    // Cleanup
    xmlXPathFreeContext(context);
    xmlXPathFreeObject (result);
    xmlFree(nodeString);
    xmlCleanupParser();

    return 0;
}

#include "expat.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>

static XML_Parser parser = NULL;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    parser = XML_ParserCreate(NULL);
    if (!parser) return 0;
    XML_SetParamEntityParsing(parser, XML_PARAM_ENTITY_PARSING_ALWAYS);
    if (XML_Parse(parser, (const char *)data, (int)size, XML_TRUE) != XML_STATUS_SUSPENDED) {
	XML_GetCurrentLineNumber(parser);
    }
    XML_ParserFree(parser);
    parser = NULL;
    return 0;    
}

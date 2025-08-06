#include "expat.h"
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <time.h>

static void XMLCALL silent_error_handler(void *userData,
                                       XML_Error error,
                                       const XML_Char *message) {

}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    XML_Parser parser = XML_ParserCreate(NULL);
    if (!parser) return 0;

    XML_SetErrorHandler(parser, silent_error_handler);

    void *buffer = XML_GetBuffer(parser, size > 0 ? size : 1);
    if (!buffer) {
        XML_ParserFree(parser);
        return 0;
    }

    if (size > 0) {
        memcpy(buffer, data, size);
    }

    uint8_t strategy = size > 0 ? data[0] % 4 : 0;

    int len;
    int isFinal;

    switch (strategy) {
        case 0:  
            len = -1;
            isFinal = 1;
            break;
        case 1:  
            len = size > 1 ? -(int)(data[1] % 100 + 1) : -1;
            isFinal = size > 2 ? data[2] % 2 : 1;
            break;
        case 2:  
            len = INT_MIN;
            isFinal = 1;
            break;
        default: 
            len = (int)size;
            isFinal = size > 0 ? data[0] % 2 : 1;
    }

    XML_ParseBuffer(parser, len, isFinal);

    if (len < 0 && XML_GetErrorCode(parser) != XML_ERROR_INVALID_ARGUMENT) {
        
    }

    XML_ParserFree(parser);
    return 0;
}
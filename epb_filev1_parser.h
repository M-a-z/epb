#ifndef EPB_FILEV1_PARSER_H
#define EPB_FILEV1_PARSER_H

#include "epb_packetReader.h"

//static const char EPB_V2_ENDTAG="";

SEpbPacketParser *init_epbfile_1_parser();
typedef struct SEpbPacketParserV1
{
    SEpbPacketParser genparser;
    int eof;
}SEpbPacketParserV1;

#endif //EPB_FILEV1_PARSER_H

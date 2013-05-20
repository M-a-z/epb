#ifndef EPB_FILEV2_PARSER_H
#define EPB_FILEV2_PARSER_H

#include "epb_packetReader.h"

#define EPBV2_HEADER_PACKET_START 1
#define MANDATORY_EPBV2_HEADER_FIELDS_MASK (EPBV2_HEADER_PACKET_START)
#define EPB_V2_ENDTAG "packet_end"

SEpbPacketParser *init_epbfile_2_parser();
typedef struct SEpbPacketParserV2
{
    SEpbPacketParser genparser;
}SEpbPacketParserV2;

#endif //EPB_FILEV2_PARSER_H

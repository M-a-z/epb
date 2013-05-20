#ifndef EPB_SNOOP_PARSER_H
#define EPB_SNOOP_PARSER_H

#include "epb_packetReader.h"

SEpbPacketParser *init_snoopfile_parser();

typedef struct SSnoop_File_hdr
{
    unsigned long long  magic_number;  //'s''n''o''o''p''\0''\0''\0'
    unsigned int        version;       // 2
    unsigned int        net;           // Ethernet == 4
}SSnoop_File_hdr;

typedef struct SSnoop_Packet_hdr
{
    unsigned int    origlen;
    unsigned int    caplen;
    unsigned int    recordlen;
    unsigned int    cumulative_drops;
    unsigned int    secs;
    unsigned int    usecs;
}SSnoop_Packet_hdr;


typedef struct SnoopStripperResults
{
    struct  SnoopStripperResults* next;
    size_t  thispiecesize;
    char    data[1];
}SnoopStripperResults;

typedef struct SEpbPacketParserSNOOP
{
    SEpbPacketParser genparser;
    SSnoop_Packet_hdr pkghdr;
    unsigned long long int timestamp;
    unsigned int compoffset;
    unsigned long recordlen;
    SnoopStripperResults *resulthead;
}SEpbPacketParserSNOOP;

#endif //EPB_SNOOP_PARSER_H

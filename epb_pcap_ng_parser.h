#ifndef EPB_PCAP_NG_PARSER_H
#define EPB_PCAP_NG_PARSER_H

#include "epb_packetReader.h"
#include "epb_pcap_hdrs.h"

#define PCAP_NG_PARSER_SUPP_OPS (EPB_PARSER_OP_PARSE )
        //| EPB_PARSER_OP_STRIP_SRC_MAC | EPB_PARSER_OP_STRIP_DST_MAC | EPB_PARSER_OP_STRIP_ETHER_TYPE )

typedef struct SpcapNgBlockCommons
{
    uint32_t block_type;
    uint32_t block_total_len;
}SpcapNgBlockCommons;


SEpbPacketParser *init_pcapngfile_parser();
typedef struct SEpbPacketParserPCAPng
{
    SEpbPacketParser genparser;
    SPcapNgSecHdrBlock filehdr;
    SpcapNgBlockCommons bcom;
    unsigned int stripoffset;
    unsigned int stripcompsize;
    size_t operation_header_size;
    unsigned long long int timestamp;
    FEpbSwap32 prepare32;
    FEpbSwap16 prepare16;
    uint32_t blockbottom;
}SEpbPacketParserPCAPng;

#endif //EPB_PCAP_PARSER_H

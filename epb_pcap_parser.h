#ifndef EPB_PCAP_PARSER_H
#define EPB_PCAP_PARSER_H

#include "epb_packetReader.h"
#include "epb_pcap_hdrs.h"

#define PCAP_PARSER_SUPP_OPS (EPB_PARSER_OP_PARSE | EPB_PARSER_OP_STRIP_SRC_MAC | EPB_PARSER_OP_STRIP_DST_MAC | EPB_PARSER_OP_STRIP_ETHER_TYPE )



SEpbPacketParser *init_pcapfile_parser();
typedef struct SEpbPacketParserPCAP
{
    SEpbPacketParser genparser;
    SPcap_File_hdr filehdr;
    SPcap_Packet_hdr pkghdr;
    unsigned int stripoffset;
    unsigned int stripcompsize;
    size_t operation_header_size;
    unsigned long long int timestamp;
    FEpbSwap32 prepare32;
    FEpbSwap16 prepare16;
}SEpbPacketParserPCAP;

#endif //EPB_PCAP_PARSER_H

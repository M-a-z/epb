#ifndef EPB_PACKET_READER_H
#define EPB_PACKET_READER_H

#include "epb.h"

#define EPB_PARSER_OP_PARSE 1ULL
#define EPB_PARSER_OP_STRIP_SRC_MAC ((EPB_PARSER_OP_PARSE)<<1ULL)
#define EPB_PARSER_OP_STRIP_DST_MAC ((EPB_PARSER_OP_STRIP_SRC_MAC)<<1ULL)
#define EPB_PARSER_OP_STRIP_ETHER_TYPE ((EPB_PARSER_OP_STRIP_DST_MAC)<<1ULL)

typedef unsigned short (*FEpbSwap16)(unsigned short);
typedef unsigned (*FEpbSwap32)(unsigned);

struct SEpbPacketParser;

unsigned short dummyswap16(unsigned short foo);
unsigned dummyswap32(unsigned foo);

typedef int (*FParseFileHeader) (struct SEpbPacketParser *, FILE *fileptr,SEpbParams *params, SCommParams *comm);
typedef int (*FParsePacketHeader) (struct SEpbPacketParser *, SEpbParams *, SCommParams *comm);
typedef void (*FAddPacketDefaults) (struct SEpbPacketParser *,SEpbParams *,SEpbParams *);
typedef int (*FParsePacketData) (struct SEpbPacketParser *,SEpbParams *,SCommParams *);
typedef void (*FUnnitPacketParserF) (struct SEpbPacketParser **);
typedef struct SEpbPacketParser * (*FInitPacketParserF)(void);
typedef int (*FParserCheckOperation) (struct SEpbPacketParser *,SCommParams *);
typedef int (*FParserFinalize)(struct SEpbPacketParser *,SEpbParams *,SCommParams *);
typedef struct SEpbPacketParser
{
    int parsertype;
    FILE *fptr;
    char *filename;
    unsigned long long      supported_operations;
    FParserFinalize finalize;
    FParserCheckOperation   check_operation;    // Ensure parser supports desired operation (currently stripping or parsing)
    FParseFileHeader        parse_fhead;        // validate file, check global header if such exist..
    FParsePacketHeader      parse_phead;        // read packet specific header and fill data
    FAddPacketDefaults      add_pkg_defs;       // add packet/sending specific info which was not in headers
    FParsePacketData        parse_pdata;        // 
    FUnnitPacketParserF     uninit_parser;
}SEpbPacketParser;


SEpbPacketParser * InitPacketParserF(int parsertype, char *filename);
int add_parser(FInitPacketParserF init,int parsertype);

#endif //EPB_PACKET_READER_H


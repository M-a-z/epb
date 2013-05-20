#include "epb_packetReader.h"

unsigned short dummyswap16(unsigned short foo)
{
    return foo;
}

unsigned dummyswap32(unsigned foo)
{
    return foo;
}



static FInitPacketParserF registered_parsers[EPB_FILE_PARSER_AMNT]={NULL};

static int check_operation(SEpbPacketParser *parser, SCommParams *comm)
{
    if( comm->operation != (comm->operation & parser->supported_operations))
    {
        printf("Requested operation is not supported with specified package file format! Did you forgot -F option?\n");
        return -1;
    }
    return 0;
}

SEpbPacketParser * InitPacketParserF(int parsertype,char *filename)
{
    SEpbPacketParser *parser=NULL;
    if(!registered_parsers[parsertype])
    {
        printf("parser for filetype %d not registered\n",parsertype);
    }
    else 
        parser = (*registered_parsers[parsertype])();
    parser->check_operation=&check_operation;
    parser->filename=filename;
    return parser;
}

int add_parser(FInitPacketParserF init,int parsertype)
{
    if(parsertype<0 || parsertype >EPB_FILE_PARSER_AMNT)
    {
        printf("%s(): Invalid parser type %d\n",__FUNCTION__, parsertype);
        return -1;
    }
    if(registered_parsers[parsertype])
    {
        printf("%s(): parser for fileformat %d already registered!\n",__FUNCTION__,parsertype);
        return -1;
    }
    registered_parsers[parsertype]=init;
    return 0;
}

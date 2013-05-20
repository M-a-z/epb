#ifndef EPB_NETMON_PARSER_H
#define EPB_NETMON_PARSER_H

#include "epb_packetReader.h"

#define NETMON_FILE_HEADER_SIZE 128
static const char netmon1_magic[] = {
    'R', 'T', 'S', 'S'
};

static const char netmon2_magic[] = {
    'G', 'M', 'B', 'U'
};

typedef struct SNetmon_File_hdr
{
    unsigned int    magic_number;
    unsigned char   ver_minor;  /* minor version number */
    unsigned char   ver_major;  /* major version number */
    unsigned short  network;    /* network type */
    unsigned short  ts_year;
    unsigned short  ts_month;
    unsigned short  ts_dow;
    unsigned short  ts_day;
    unsigned short  ts_hour;
    unsigned short  ts_min;
    unsigned short  ts_sec;
    unsigned short  ts_msec;
    unsigned int    frametableoffset;
    unsigned int    frametablelength;
    unsigned int    userdataoffset;
    unsigned int    userdatalength;
    unsigned int    commentdataoffset;
    unsigned int    commentdatalength;
    unsigned int    statisticsoffset;
    unsigned int    statisticslength;
    unsigned int    networkinfooffset;
    unsigned int    networkinfolength;
}SNetmon_File_hdr;

typedef struct SNetmon_1_Packet_hdr
{
    unsigned int    ts_delta;   /* msecs */
    unsigned short  origlen;
    unsigned short  caplen;

}SNetmon_1_Packet_hdr;

typedef struct SNetmon_2_Packet_hdr
{
    unsigned int ts_delta_lo;    /*  usecs */
    unsigned int ts_delta_hi;    /* usecs */
    unsigned int origlen;
    unsigned int caplen;
}SNetmon_2_Packet_hdr;

SEpbPacketParser *init_netmonfile_parser();
typedef struct SEpbPacketParserNETMON
{
    SEpbPacketParser genparser;
    unsigned long long int timestamp;
    unsigned int *ftable;
    unsigned int frametablelen;
    unsigned int curr_frame;
    unsigned int captured_frames;
}SEpbPacketParserNETMON;

#endif //EPB_NETMON_PARSER_H

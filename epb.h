#ifndef EPB_H
#define EPB_H


#include <errno.h>
#include <ifaddrs.h>
#include <linux/if_ether.h>
#include <netdb.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <getopt.h>



#define VERSION "1.7 - rc"
#define EPB_FILE_PARSER_AMNT 6
#define EPB_FILE_PARSER_EPB 0
#define EPB_FILE_PARSER_EPB2 1
#define EPB_FILE_PARSER_PCAP 2
#define EPB_FILE_PARSER_SNOOP 3
#define EPB_FILE_PARSER_NETMON 4
#define EPB_FILE_PARSER_PCAPNG 5


#define PARSER_READ_EOF 1


#pragma pack(push,1)

typedef struct SEpbEthHdr
{
    u_char destination[ETHER_ADDR_LEN];
    u_char source[ETHER_ADDR_LEN];
    u_short ether_type;
}SEpbEthHdr;


typedef struct SEpbIpHdr
{
    u_char ip_vhl;
    u_char ip_typeOfService;
    u_short ip_totalLen;
    u_short ip_id;
    u_short ip_fragmentOffset_andFlags;
    u_char ip_timeToLive;
    u_char ip_protocol;
    u_short checksum;
    uint32_t ip_source;
    uint32_t ip_destination;
}SEpbIpHdr;

typedef struct SEpbIpPkg
{
    SEpbEthHdr eth_hdr;
    SEpbIpHdr ip_hdr;
}SEpbIpPkg;

#pragma pack(pop)

extern int do_htons;
extern int fillcsum;

struct SCommParams;
struct SEpbParams;

typedef struct SEpbParams
{
    struct SEpbParams *next;
    int pkgno;
    unsigned int pkg_amnt;         ///< How many pkgs are sent
    unsigned int startdelay;       ///< How many micro seconds are waited after sender is started.
    unsigned int interval;         ///< How many microsecs are slept between sends
//    char ifname[32];
    unsigned int pkg_size;
    unsigned char pkg[1];
}SEpbParams;

typedef int (*Fpreparefunc)(SEpbParams *params, struct SCommParams *comm);
typedef int (*Fdofunc)(SEpbParams *,struct SCommParams *comm);
typedef int (*Ffinishfunc)(SEpbParams *,struct SCommParams *comm);

typedef struct SCommParams
{
    int sock;
    struct sockaddr_ll device;
    unsigned int filever;
    unsigned long long operation;
    char strip_file_ext[32];
    char *stripmacs;
    unsigned int use_realmac;
    char real_mac[6];
    unsigned char stripcompdata[6];
    size_t stripcompsize;
    char ifname[33];
    FILE *outputfile;
    Fdofunc dofunc;
    Ffinishfunc finishfunc;
    Fpreparefunc prepfunc;
    char target[32];
    char *filename;
    void *filedata;  /* In case of stripping, data is filled here in finalize */
    size_t filesize; /* In case of stripping, this is data size */
}SCommParams;




#endif

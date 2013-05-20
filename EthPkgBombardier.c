/****************************************************************/
/*                                                              *
 *                    LICENSE for EPB                           *
 *                                                              *
 *  It is allowed to use this program for free, as long as:     *
 *                                                              *
 *      -You use this as permitted by local laws.               *
 *      -You do not use it for malicious purposes like          *
 *      harming networks by messing up arp tables etc.          *
 *      -You understand and accept that any harm caused by      *
 *      using this program is not program author's fault.       *
 *      -You let me know if you liked this, my mail             *
 *      Mazziesaccount@gmail.com is open for comments.          *
 *                                                              *
 *  It is also allowed to redistribute this program as long     *
 *  as you maintain this license and information about          *
 *  original author - Matti Vaittinen                           *
 *  (Mazziesaccount@gmail.com)                                  *
 *                                                              *
 *  Modifying this program is allowed as long as:               *
 *                                                              *
 *      -You maintain information about original author/SW      *
 *      BUT also add information that the SW you provide        *
 *      has been modified. (I cannot provide support for        *
 *      modified SW.)                                           *
 *      -If you correct bugs from this software, you should     *
 *      send corrections to me also (Mazziesaccount@gmail.com   *
 *      so I can include fixes to official version. If I stop   *
 *      developing this software then this requirement is no    *
 *      longer valid.                                           *
 *                                                              *
 *                                                              *
 *                                                              *
 *                                                              *
 ****************************************************************/



#include <arpa/inet.h>
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
#include "epb.h"
#include "epb_packetReader.h"
#include "epb_filev1_parser.h"
#include "epb_filev2_parser.h"
#include "epb_pcap_parser.h"
#include "epb_snoop_parser.h"
#include "epb_netmon_parser.h"
#include "epb_helpers.h"
#include "epb_pcap_ng_parser.h"


#define OPTSTRING "a:cC:d:eE:f:F:hHi:j:mn:s:St:T:u:vw?"
#define HELP_PRINT \
"Required args:\n"\
"    -f --file              file where packet is specified\n" \
"or\n"\
"    -S --stdin             read package specification from stdin\n" \
"    -n --outif             followed by interface name to determine out interface\n" \
"or\n"\
"    -t --targetip          followed by target IP (used only to determine out interface)\n\n" \
"or\n"\
"    -C,-T,-E --strip-src-mac, --strip-dst-mac, --strip-ether-type \n"\
"                           followed by mac address or 16bit ether type value. These make epb to run in strip mode to generate new packet \n"\
"                           file with only certain packets instead of sending anything\n" \
"or\n" \
"    -H --humanreadable     Convert specified capture file to human readable and editable epb version 2\n" \
"                           file instead of sending a thing\n" \
"Optional args:\n" \
"    -F --fileversion       packet file version (defaults to 1), see below. Supported values: 1,2,pcap,snoop,netmon (versions 1 and 2)\n" \
"    -s --pkgsize           package size if 1500 is not big enough \n" \
"    -j --interval-sec      interval (sec) - delay between packages defaults to 1 sec\n" \
"    -i --interval-millisec interval (msec) - delay between packages defaults to 1000 msec\n" \
"    -u --interval-microsec interval (micro sec) - delay between packages defaults to 1000000 micro sec\n" \
"    -d --delay             delay - delay before sending first package, defaults to 0 sec\n" \
"    -a --pkgamount         amount of packages to send (defaults to 1) \n" \
"    -w --block             wait for packets being sent\n" \
"    -m --realmac           mac from HW - use real mac as source address\n"\
"    -e --keependianess     endianess as given, do not do byte order conversions but send data as specified in file\n" \
"                           NOTE: endianess change is only done when packet is specified in epb file formats\n" \
"    -c --keepchecksum      checksum as is - even if protocol was recognized and checksum was zero, leave it as is \n" \
"                           NOTE: checksum filling is only done when packet is specified in epb file formats.\n" \
"    -v --version           display version and exit\n" \
"    -h --help              to get this help\n" \
"    -?                     to get this help\n\n" \
"NOTE: -f is required as is either -n, -t, -C, -T or -E\n" \
" -C, -T and -E make epb to run in \"strip mode\" which is used to strip part of packets from original packet specification file.\n\n" \
"Packet files:\n" \
"Version 1:\n" \
"    Version 1 packet file simply lists data to be sent as single packet. Data is specified in text file.\n" \
"    File consists of rows, specifying packet data as datatype:value pairs. Possible datatypes are\n" \
"    u8, u16, u32, u64, i8, i16, i32 and i64 - which convert the given value to 8, 16, 32 or 64 bit signed/\n" \
"    unsigned integer. Lines prefixed with # are interpretred as comments.\n\n" \
"Version 2:\n" \
"    Version 2 packet file supports specifying sequence of packets. Version 2 packet file must begin with line\n" \
"    --epb-file-version=2--\n" \
"    Packet contents are specified similar to version 1. In order to support sending multiple packets, a header must be\n" \
"    added before each packet. Header consists of mandatory and optional fields. Each header field must be\n" \
"    started with ! character. Field may contain specifier and value, or plain specifier.\n" \
"    Each package must be ended with !packet_end field.\n" \
"    Mandatory header fields (each packet MUST be prepended with header specifying these fields):\n" \
"      !packet_start\n" \
"        this must be the first field stating start of the new packet.\n" \
"      !header_end\n" \
"        this must be the last field in header (just before actual packet data)\n" \
"    Optional fields:\n" \
"      !uenddelay <delay>\n" \
"      example: !uenddelay 1000\n" \
"        specifies microsecond delay before sending next packet. Defaults to 1000000\n" \
"      !enddelay <delay>\n" \
"      example: !enddelay 3\n" \
"        specifies second delay before sending next packet. Defaults to 1\n" \
"      !ustartdelay <delay>\n" \
"      example: !ustartdelay 1000\n" \
"        specifies microsecond delay before sending this packet. Defaults to 0\n" \
"      !startdelay <delay>\n" \
"      example: !startdelay 3\n" \
"        specifies second delay before sending this packet. Defaults to 0\n" \
"      !repeat <amount>\n" \
"      example: !repeat 3\n" \
"        can be used to send <amount> similar packets. NOTE: enddelay impacts to repeated packets\n" \
"        startdelay affects only to first packet\n\n" \
"Version pcap:\n" \
"    Vertsion pcap is for sending packets specified in pcap (libcap) file format. Pcap is de-facto packet specification\n" \
"    file format in free world. Most of the popular free tools like tcpdump, wireshark etc work with pcap. \n" \
"    epb now includes pcap format support. Epb can also strip only packets targeted to / originating from certain mac address.\n\n" \
"Version snoop:\n" \
"    SUN's snoop packet sniffer file format (version 2). Stripping support added to snoop format too.\n\n" \
"Version netmon:\n" \
"    Microsoft's Netmon capturer's file format (versions 1 and 2)\n\n"

static struct option long_options[] =
{
    {"file" , required_argument, 0, 'f'},
    {"fileversion" , required_argument, 0, 'F'},
    {"stdin" , no_argument, 0, 'S'},
    {"outif", required_argument, 0, 'n'},
    {"targetip",  required_argument, 0, 't'},
    {"version",  no_argument, 0, 'v'},
    {"humanreadable",  no_argument, 0, 'H'},
    {"pkgsize",  required_argument, 0, 's'},
    {"interval-sec", required_argument, 0, 'j'},
    {"interval-millisec", required_argument, 0, 'i'},
    {"interval-microsec", required_argument, 0, 'u'},
    {"delay", required_argument, 0, 'd'},
    {"pkgamount", required_argument, 0, 'a'},
    {"block", no_argument, 0, 'w'},
    {"realmac", no_argument, 0, 'm'},
    {"help",  no_argument, 0, 'h'},
    {"keependianess", no_argument, 0, 'e'},
    {"keepchecksum", no_argument, 0, 'c'},
    {"strip-src-mac", required_argument, 0, 'C'},
    {"strip-dst-mac", required_argument, 0, 'T'},
    {"strip-ether-type", required_argument, 0, 'E'},
    {0,0,0,0}
};

static char *G_exename;

int do_htons=1;
int fillcsum=1;

static int getrealmac(char *ifname, char *macbuff)
{
    struct ifreq ifr;
    int sock;
//    char *macbuff = malloc(6);

    if(!macbuff)
    {
        printf("badmac\n");
        goto err_out;
    }

    if(-1==(sock=socket(PF_INET,SOCK_STREAM,0)))
    {
        printf("Failed to open socket for mac obtaining ioctl!\n");
        goto err_out;
    }
    strncpy(ifr.ifr_name,ifname,sizeof(ifr.ifr_name)-1);
    ifr.ifr_name[sizeof(ifr.ifr_name)-1]='\0';
/*
    if(-1==ioctl(sock,SIOCGIFADDR,&ifr))
    {
        printf("SIOCGIFADDR failed => can't get mac!\n");
        goto err_close_sock_out;
    }
    */
    if(-1==ioctl(sock, SIOCGIFHWADDR, &ifr))
    {
        printf("SIOCGIFHWADDR failed => can't get mac!\n");
        goto err_close_sock_out;
    }
    memcpy(macbuff,ifr.ifr_hwaddr.sa_data,6);
    close(sock);
    if(0)
    {
err_close_sock_out:
        close(sock);
err_out:
        return -1;
    }
    return 0;
}

static void print_usage()
{
    printf("\nUsage:\n\n\n");
    printf("%s <optional options> -n <ifname> -f <pkgfile>\n\n",G_exename);
    printf(HELP_PRINT);
#if 0
    printf("\n\n\n\npkgfile format:\n\n");
    printf("packages to be sent must be specified in a text file using following format:\n");
    printf("valuetype:value\n");
    printf("The valuetype is a C - like datatype, consisting of one character signedness specifier u or i,\n\
            and data lenght specifier 8,16,32 or 64 (amount of bits).\n");
    printf("Value is the value of this field. Eg, 16 bit wide identification field in IP header, could be specified to be 255 as follows\n\
            u16:255    or\n\
            u16:0xff\n");
    printf("lines beginning with #-mark are interpreted to be comments.\n\n");
    printf("NOTE: Only 1 width:value pair / line is supported!\n");
#endif
}

/*
void fill_nonfilevalues_v2(SEpbParams *paramhead,SEpbParams *newpkg)
{
    if(!newpkg->pkg_amnt)
    {
        if(paramhead->pkg_amnt)
            newpkg->pkg_amnt=paramhead->pkg_amnt;
        else
            newpkg->pkg_amnt=1;
    }
    if(!newpkg->pkg_size)
    {
        if(paramhead->pkg_size)
            newpkg->pkg_size=paramhead->pkg_size;
        else
            newpkg->pkg_size=1500;
    }

    if(!newpkg->interval)
    {
        if(paramhead->interval)
            newpkg->interval=paramhead->interval;
        else
            newpkg->interval=1000000;
    }


    memcpy(newpkg->target,paramhead->target,sizeof(paramhead->target));
    memcpy(newpkg->sender_mac,paramhead->sender_mac,sizeof(paramhead->sender_mac));
    memcpy(newpkg->ifname,paramhead->ifname,sizeof(paramhead->ifname));
}
*/
/*
typedef struct eth_bombargs
{
    int sock;
    struct sockaddr_ll device;
    SEpbParams *params;
}eth_bombargs;
*/


static void testprintit(char *data, size_t size)
{
    int i;
    for(i=0;(i+4)<=size;i+=4)
    {
        printf("%02hhx %02hhx %02hhx %02hhx\n",data[i+0],data[i+1],data[i+2],data[i+3]);
    }
    if(i<size)
    {
        int j=0;
        while(j+i<size)
        {
            printf("%02hhx ",data[i+j]);
            j++;
        }
        printf("\n");
    }
    fflush(stdout);
}
static int finish_filewrite(SEpbParams *params, SCommParams *comm)
{
    if(1!=fwrite(comm->filedata,comm->filesize,1,comm->outputfile))
    {
        printf("Failed to write packet in file!\n");
        return -1;
    }
    fclose(comm->outputfile);
    return 0;
}
static int prepare_filewrite(SEpbParams *params, SCommParams *comm)
{
    char filename[1024];
    //FILE *writefile;
    SEpbParams *tmp;
    char *basenames[3]={"src","dst","ethertype"};
    int i;

    if(EPB_PARSER_OP_PARSE != comm->operation)
    {
        for(i=0;!(((EPB_PARSER_OP_STRIP_SRC_MAC)<<i)&comm->operation);i++);

        if(i>3)
        {
            printf("Invalid operation!\n");
            return -1;
        }

        snprintf
        (
            filename,
            1024,
            "epb_stripped_%s.%s.%s",
            basenames[i],
            comm->stripmacs,
            comm->strip_file_ext
        );
    }
    else
    {
        strcpy(filename,"epb_converted.packet");
    }
    if(!(comm->outputfile=fopen(filename,"w")))
    {
        printf("Failed to open file %s for writing\n",filename);
        return -1;
    }
    if(EPB_PARSER_OP_PARSE == comm->operation)
    {
        const char epbfilever[]="--epb-file-version=2--\n";
        comm->filesize=sizeof(epbfilever)-1;
        comm->filedata=malloc(comm->filesize);
        if(!comm->filedata)
        {
            printf("malloc FAILED!\n");
            return -1;
        }
        memcpy(comm->filedata,epbfilever,comm->filesize);
        return 0;
    }
    for(tmp=params;params->next;params=tmp)
    {
        free(tmp->next);
        params->next=NULL;
        tmp=tmp->next;
    }
    return 0;
}
static int doconvert(SEpbParams *params, SCommParams *comm)
{
    char *newdataptr;
    size_t newdatasize=2048;
    size_t offset;
    size_t written;
    int i;
    
    if(!params || !comm)
        return -1;
    newdataptr=malloc(newdatasize);
    if(!newdataptr)
    {
        printf("malloc FAILED!\n");
        return -1;
    }
    if
    (
        newdatasize<=
        (
            written=
            snprintf
            (
                newdataptr,
                newdatasize,
                "#packet number %d\n!packet_start\n!ustartdelay %u\n!enddelay %u\n!header_end\n",
                params->pkgno,
                params->startdelay,
                params->interval
            )
        )
    )
    {
        printf("Odd Failure!\n");
        return -1;
    }
    offset=written;
    for(i=0;i<params->pkg_size;i++)
    {
retry:
        if(newdatasize-offset<=(written=snprintf(newdataptr+offset,newdatasize-written,"u8:0x%02x\n",(unsigned int)params->pkg[i])))
        {
            /* revert written back */
            written=offset;
            newdatasize+=2048;
            newdataptr=realloc(newdataptr,newdatasize);
            if(!newdataptr)
            {
                printf("realloc FAILED!\n");
                return -1;
            }
            goto retry;
        }
        written=(offset+=written);
    }
retry2:
    if(newdatasize-offset<=(written=snprintf(newdataptr+offset,newdatasize-written,"!packet_end\n")))
    {
        newdatasize+=written;
        written=offset;
        newdataptr=realloc(newdataptr,newdatasize);
        if(!newdataptr)
        {
            printf("realloc FAILED!\n");
            return -1;
        }
        printf("goto retry2\n");
        goto retry2;
    }
    written=(offset+=written);
    comm->filedata=realloc(comm->filedata,comm->filesize+written);
    if(!comm->filedata)
    {
        printf("Realloc FAILED, long trace perhaps? Sorry, I'm dummy and always try reading WHOLE capture on memory :(\n");
        return -1;
    }
    memcpy(&(((char *)comm->filedata)[comm->filesize]),newdataptr,written);
    comm->filesize+=written;
    free(newdataptr);
    return 0;
}
static int dosend(SEpbParams *params, SCommParams *comm)
{
    void *pkgtosend;
    usleep(params->startdelay);

/* Prepare package */
    pkgtosend=&(params->pkg[0]);
//    printf("sending:\n");
    testprintit(pkgtosend, params->pkg_size);

    for(;params->pkg_amnt;params->pkg_amnt--)
    {
        if(-1==sendto(comm->sock,pkgtosend,params->pkg_size, 0, (struct sockaddr *)&comm->device, sizeof(comm->device)))
        {
            printf("sendto() failed: %s\n",strerror(errno));
            return -1;
        }
        if(params->interval>0)
        {
            usleep(params->interval);
            if(params->interval>500000)
            {
                putchar('.');
                fflush(stdout);
            }

        }
    }
    if(params->interval>500000)
        printf("\n");
    return 0;
}
static int prepare_send(SEpbParams *params, SCommParams *comm)
{
    struct ifreq ifr;
    if(0>(comm->sock = socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ALL))))
    {
        printf("PF_PACKET sock failed, ()%s\n",strerror(errno));
        return EXIT_FAILURE;
    }
//    memset(&device,0,sizeof(device));
    strncpy((char *)&(ifr.ifr_name),comm->ifname,sizeof(ifr.ifr_name));
    printf("Using Device: '%s'",comm->ifname);
    if(ioctl(comm->sock,SIOCGIFINDEX,&ifr))
    {
        /* ErrorTerror */
        printf("SIOCGIFINDEX failed %d\n",errno);
        return EXIT_FAILURE;
    }
    comm->device.sll_family=AF_PACKET;
    comm->device.sll_ifindex=ifr.ifr_ifindex;
    comm->device.sll_halen=htons(6);
    printf("Starting pkg generation\n");
    return 0;
}

static int EthBombardier(SEpbParams *params, SCommParams *comm)
{
    //int sock;
    int rval;
    int i;
    rval= (*comm->prepfunc)(params,comm);
    if(rval)
        return rval;

    if(comm->dofunc)
        for(i=(params->pkgno=0);params;params=params->next,i++)
        {
            params->pkgno=i;
            if((*comm->dofunc)(params,comm))
            {
                printf("Failed to process package\n");
                return EXIT_FAILURE;
            }
        }
    if(comm->finishfunc)
        if( (*comm->finishfunc)(params,comm))
        {
            printf("Failed to finish package handling\n");
            return EXIT_FAILURE;
        }
    for(;params;params=params->next)
        free(params);
    if(-1!=comm->sock && 0!=comm->sock)
        close(comm->sock);
    return 0;
}
/* This kind of false assumptions MAY be done in code... :( */
static void intlencheck()
{
    if(sizeof(void *) != 4)
    {
        printf("WARNING! You're running with machine where pointer is %u bytes - %s is tested with 4 byte pointers only\n",sizeof(void *),G_exename);
        printf("If you encounter problems, please fix or report them (to matti.vaittinen@nsn.com - 05/2012).\n");
    }

    if(sizeof(int) != 4)
    {
        printf("WARNING! You're running with machine where int size is %u bytes - %s is tested with 4 bytes ints only\n",sizeof(int),G_exename);
        printf("If you encounter problems, please fix or report them (to matti.vaittinen@nsn.com - 05/2012).\n");
    }
    if(sizeof(long) != 4)
    {
        printf("WARNING! You're running with machine where long int size is %u bytes - %s is tested with 4 bytes long ints only\n",sizeof(long),G_exename);
        printf("If you encounter problems, please fix or report them (to matti.vaittinen@nsn.com - 05/2012).\n");
    }
    if(sizeof(short) != 2)
    {
        printf("WARNING! You're running with machine where short int size is %u bytes - %s is tested with 2 bytes short ints only\n",sizeof(short),G_exename);
        printf("If you encounter problems, please fix or report them (to matti.vaittinen@nsn.com - 05/2012).\n");
    }
    if(sizeof(long long) != 8)
    {
        printf("WARNING! You're running with machine where long long int size is %u bytes - %s is tested with 8 bytes long long ints only\n",sizeof(long long),G_exename);
        printf("If you encounter problems, please fix or report them (to matti.vaittinen@nsn.com - 05/2012).\n");
    }

}

static void hiawathacheck()
{
    short i=1;
    char *pi=(char *)&i;
    if(!*pi)
    {
        printf("WARNING! You're running big endian machine - %s is tested with little endian machines only.\n",G_exename);
        printf("If you encounter problems, please fix or report them (to matti.vaittinen@nsn.com - 05/2012).\n");
    }
}

static void doenvchecks()
{
    hiawathacheck();
    intlencheck();
}

SEpbParams *start_pkgdata_filling(SEpbParams *params,SEpbPacketParser *parser,int magicflag,SCommParams *comm)
{
    SEpbParams *paramhead=params;
    SEpbParams *newpkg;
    SEpbParams *prevpkg;

    FILE *rfile;

    if(!params || !parser)
    {
        printf("NULL arg %s()!\n",__FUNCTION__);
        return NULL;
    }
    if(magicflag!=2)
        rfile=fopen(comm->filename,"r");
    else
        rfile=stdin;
    if(NULL==rfile)
    {
        printf("pkg file (%s) open FAILED (%s)\n",comm->filename,strerror(errno));
        return NULL;
    }
    if(parser->check_operation(parser,comm))
    {
        printf("Unsupported operation for this file format\n");
        return NULL;
    }
    if(parser->parse_fhead)
        if(parser->parse_fhead( parser, rfile, params,comm ))
        {
            printf("bad packet file type!\n");
            return NULL;
        }
    for(prevpkg=paramhead;1;prevpkg=newpkg)
    {
        int rval;
        newpkg=calloc(1,sizeof(SEpbParams));
        if(NULL==newpkg)
        {
            printf("calloc FAILED\n");
            return NULL;
        }
        /* Read header */
        if(parser->parse_phead)
            if((rval=parser->parse_phead(parser,newpkg,comm)))
            //if((rval=init_filev2_pkgspecs(newpkg,rfile)))
            {
                if(rval==PARSER_READ_EOF)
                {
                    break;
                }
                printf("Failed to parse package file (packet header corruption)\n");
                return NULL;
            }

        /* Fill defaults / given values if no vals found from header */
        if(parser->add_pkg_defs)
            parser->add_pkg_defs(parser,newpkg,paramhead);
        printf("newpkg->pkg_size=%d\n",newpkg->pkg_size);
        newpkg=realloc(newpkg,sizeof(SEpbParams)+newpkg->pkg_size-1);

        if(NULL==newpkg)
        {
            printf("realloc FAILED!\n");
            return NULL;
        }
        printf("newpkg->pkg_size=%d\n",newpkg->pkg_size);
        if((rval=parser->parse_pdata(parser,newpkg,comm)))
        {
            if(rval==PARSER_READ_EOF)
            {
                printf("Premature file ending?\n");
                return NULL;
            }
            printf("Error while parsing package file!\n");
            return NULL;
        }
        prevpkg->next=newpkg;
    }
    if(!paramhead || !paramhead->next)
        return NULL;
    if(parser->finalize)
        if( (*parser->finalize)(parser,paramhead,comm))
        {
            printf("Failed to complete file parsing\n");
        }
    return paramhead->next;
}

static int find_interface(char *ifname,char *target)
{
    /* ifname and target both should be max 31 chars + NULL */
    int sock;
    struct sockaddr_in ad;
    sock=socket(AF_INET,SOCK_DGRAM,0);
    if(sock < 0)
    {
        printf("socket creation FAILED\n");
        goto err_out;
    }
    memset(&ad,0,sizeof(ad));
    if(1!=inet_pton(AF_INET,target,&ad.sin_addr))
    {
        printf("Failed to convert ip %s",target);
        goto err_out;
    }
    ad.sin_family=AF_INET;
    if(0!=connect(sock,(const struct sockaddr *)&ad,sizeof(ad)))
    {
        printf("failed to determine interface name based on IP %s\n",target);
        goto err_out;
    }
    else
    {
        struct sockaddr_in name;
        int namelen;
        int rval;

        /* hackkikakki */
        int not_found = -1;
        struct ifaddrs *addrs, *iap;
        struct sockaddr_in *sa;


        if((rval=getsockname(sock, (struct sockaddr *)&name, (socklen_t *)&namelen)))
        {
            printf("sockname failed! %d\n", rval);
            goto err_out;
        }
        
        /* and further hackki */
        if(getifaddrs(&addrs))
        {
            printf("Internal Error - getifaddrs FAILED!\n");
            goto err_out;
        }
        for(iap = addrs; iap && not_found ; iap = iap->ifa_next)
        {
            sa = (struct sockaddr_in *) (iap->ifa_addr);
            if(*((int *)&(sa->sin_addr)) == *((int *)&(name.sin_addr)))
            {
                not_found=0;
                if(strlen(iap->ifa_name)>31)
                {
                    printf("Internal Error - can't handle %u chars wide interface %s",strlen(iap->ifa_name),iap->ifa_name);
                    freeifaddrs(addrs);
                    goto err_out;
                }
                strcpy(ifname,iap->ifa_name);
            }
        }
        freeifaddrs(addrs);
                
        close(sock);
        return not_found;
    }
err_out:
    if(sock >= 0)
        close(sock);
    return -1;
}

void set_defaults(SEpbParams *params, SCommParams *comm)
{
    memset(comm,0,sizeof(SCommParams));
    memset(params,0,sizeof(SEpbParams));
    params->pkg_amnt=1;
    params->startdelay=0;
    params->interval=1000000;
    comm->finishfunc=NULL;
    comm->operation=EPB_PARSER_OP_PARSE;
    comm->prepfunc=&prepare_send;
    comm->dofunc=&dosend;
}

int parsers_register()
{
    int rval=0;
    rval+=add_parser(&init_epbfile_1_parser,0);
    rval+=add_parser(&init_epbfile_2_parser,1);
    rval+=add_parser(&init_pcapfile_parser,2);
    rval+=add_parser(&init_snoopfile_parser,3);
    rval+=add_parser(&init_netmonfile_parser,4);
    rval+=add_parser(&init_pcapngfile_parser,5);
    return rval;
}

static int getmacarg(char *macstring,unsigned char *mac)
{
    int rval;
    unsigned m0,m1,m2,m3,m4,m5;
    short i=1;
    char *pi=(char *)&i;
    if(!macstring)
    {
        printf("no mac for packets to strip specified!\n");
        return EXIT_FAILURE;
    }
    if(!*pi) 
        rval=sscanf(macstring,"%x:%x:%x:%x:%x:%x",&m5,&m4,&m3,&m2,&m1,&m0 );
    else
        rval=sscanf(macstring,"%x:%x:%x:%x:%x:%x",&m0,&m1,&m2,&m3,&m4,&m5 );
    if(6!=rval || 255<m0 || 255<m1 || 255<m2 || 255<m3 || 255<m4 || 255<m5)
    {
        printf("Invalid strip mac '%s' given\n",macstring);
        return EXIT_FAILURE;
    }
    mac[0]=(unsigned char)m0;
    mac[1]=(unsigned char)m1;
    mac[2]=(unsigned char)m2;
    mac[3]=(unsigned char)m3;
    mac[4]=(unsigned char)m4;
    mac[5]=(unsigned char)m5;
    return 0;
}

int main(int argc, char *argv[])
{
    int rval=0;
    int convert =0;
    int c;
    int ip_given=0;
    int filename_given=0;
    int ifname_given=0;
    SEpbParams *params;
    unsigned int interval_multiplier=1;
    unsigned int tmpival=0;
    unsigned int str_len;
    int nodaemon=0;
    int index;
    SCommParams comm;
    /* Parse args */
    G_exename=argv[0];
    doenvchecks();
    params=malloc(sizeof(SEpbParams));
    if(NULL==params)
    {
        printf("param malloc FAILED!");
        goto err_end;
    }
    set_defaults(params,&comm);
    index=0;
    if(parsers_register())
    {
        printf("Failed to register some file parsers...\n");
        goto err_end;
    }
    params->pkg_size=1500;
    while(-1 != (c = getopt_long(argc, argv, OPTSTRING,long_options,&index)))
    {
        switch(c)
        {
            case 'm':
                comm.use_realmac=1;
            case 'c':
                fillcsum=0;
                break;
            case 'w':
                nodaemon=1;
                break;
            case 'v':
                printf("%s version %s\n",argv[0],VERSION);
                goto end;
                break;
            case '?':
            case 'h':
                printf("%s version %s\n",argv[0],VERSION);
                print_usage();
                goto end;
                break;
            case 'e':
                do_htons=0;
                break;
            case 'a':
                if(argchk(optarg, 0, 0xFFFFFFFF,(unsigned long *) &(params->pkg_amnt)))
                {
                    printf("Failed to parse package amount\n");
                    goto err_end;
                }
                break;
            case 'd':
                if(argchk(optarg, 0, 0xFFFFFFFF/1000000,(unsigned long *) &(params->startdelay)))
                {
                    printf("Failed to parse start delay\n");
                    goto err_end;
                }
                params->startdelay*=1000000;
                break;
            case 'j':
                interval_multiplier*=1000;
            case 'i':
                interval_multiplier*=1000;
            case 'u':
                
                if(argchk(optarg, 0, 0xFFFFFFFFUL/interval_multiplier,(unsigned long *) &tmpival))
                {
                    printf("Failed to parse interval\n");
                    goto err_end;
                }
                params->interval=tmpival*interval_multiplier;
                break;
            case 't':
                /* target IP */
                if((str_len=strlen(optarg))>=32)
                {
                    printf("host too long, max 32 bytes\n");
                    goto err_end;
                }
                else
                {
                    memcpy(comm.target,optarg,str_len+1);
                    ip_given=1;
                }
                break;
            case 'n':
                if((str_len=strlen(optarg))>=32)
                {
                    printf("ifname too long, max 32 bytes\n");
                    goto err_end;
                }
                else
                {
                    memcpy(comm.ifname,optarg,str_len);
                    ifname_given=1;
                }
                break;
            case 's':
                if(argchk(optarg, 0, 0xffff,(unsigned long *) &(params->pkg_size)))
                {
                    printf("Failed to parse package size\n");
                    goto err_end;
                }
                break;

            case 'f':
            {
                if(NULL==optarg)
                {
                    printf("file name required for package data\n");
                    goto err_end;
                }
                comm.filename=optarg;
                filename_given=1;
                break;
            }
            case 'H':
            {
                convert=1;
                comm.dofunc=&doconvert;
                comm.finishfunc=&finish_filewrite;
                comm.prepfunc=&prepare_filewrite;
            }
            break;
            case 'E':
            {
                unsigned foo;
                unsigned short bar;
                if(argchk(optarg,0,0xFFFF,(unsigned long *) &foo))
                {
                    printf("Invalid ether type (%s) given\n",optarg);
                    goto err_end;
                }
                bar=htons((unsigned short )foo);
                memcpy(&(comm.stripcompdata),&bar,sizeof(bar));
                comm.stripcompsize=2;
                /* misusing stripmacs field...*/
                comm.stripmacs=optarg;
                comm.dofunc=NULL;
                comm.finishfunc=&finish_filewrite;
                comm.prepfunc=&prepare_filewrite;
                comm.operation=EPB_PARSER_OP_STRIP_ETHER_TYPE;
            }
            break;
            case 'T':
                if(getmacarg(optarg,comm.stripcompdata))
                {
                    printf("Invalid strip dst mac '%s' given!\n",optarg);
                    goto err_end;
                }
                comm.stripcompsize=6;
                comm.stripmacs=optarg;
                comm.dofunc=NULL;
                comm.prepfunc=&prepare_filewrite;
                comm.finishfunc=&finish_filewrite;
                comm.operation=EPB_PARSER_OP_STRIP_DST_MAC;
            break;
            case 'C':
                if(getmacarg(optarg,comm.stripcompdata))
                {
                    printf("Invalid strip dst mac '%s' given!\n",optarg);
                    goto err_end;
                }
                comm.stripcompsize=6;
                comm.dofunc=NULL;
                comm.prepfunc=&prepare_filewrite;
                comm.finishfunc=&finish_filewrite;
                comm.stripmacs=optarg;
                comm.operation=EPB_PARSER_OP_STRIP_SRC_MAC;

            break;
            case 'F':
                if(argchk(optarg, 1, EPB_FILE_PARSER_AMNT,(unsigned long *) &(comm.filever)))
                {
                    if(!strcmp(optarg,"pcap"))
                    {
                        comm.filever=EPB_FILE_PARSER_PCAP;
                        break;
                    }
                    else if(!strcmp(optarg,"snoop"))
                    {
                        comm.filever=EPB_FILE_PARSER_SNOOP;
                        break;
                    }
                    else if(!strcmp(optarg,"netmon"))
                    {
                        comm.filever=EPB_FILE_PARSER_NETMON;
                        break;
                    }
                    else if(!strcmp(optarg,"pcapng"))
                    {
                        comm.filever=EPB_FILE_PARSER_PCAPNG;
                        break;
                    }
                    else
                        printf("unrecognized epb file format %s\n",optarg);
                    goto err_end;
                }
                comm.filever--;
            break;
            case 'S':
            filename_given=2;
            comm.filename=malloc(6);
            if(!comm.filename)
            {
                printf("Malloc FAILED!!\n");
                goto err_end;
            }
            memcpy(comm.filename,"stdin",6);
            break;
            default:
                break;
        }
    }
    if(!filename_given)
    {
        printf("Name of package file or --stdin REQUIRED\n");
        goto err_end;
    }
    if(comm.operation == EPB_PARSER_OP_PARSE && !convert)
    {
        if(!ip_given && !ifname_given)
        {
            printf("\nEither -n with out interface name, or -t with targer IP are required!\n");
            printf("Use %s -h for more detailed help\n",G_exename);
            goto err_end;
        } 
        if(!do_htons) 
        {
            if(comm.filever>1)
            {
                printf("-e (--keependianess) is only supported with epb packet file formats 1 and 2 (-F1 and -F2)\n");
                goto err_end;
            }
        }
        if(!ifname_given)
        {
            if(find_interface((char *)comm.ifname,(char *)comm.target))
            {
                printf("Failed to find out interface for target %s\n",(NULL==comm.target)?"(NULL)":comm.target);
                goto err_end;
            }
        }
    }
    if(comm.use_realmac)
    {
        if(getrealmac(comm.ifname,&(comm.real_mac[0])))
            goto err_end;
    }
    if((unsigned)comm.filever < EPB_FILE_PARSER_AMNT)
    {
        SEpbPacketParser *parser=InitPacketParserF(comm.filever,comm.filename);
        if(!parser)
        {
            printf("Failed to create parser for file version %d",comm.filever);
            goto err_end;
        }
        if(!(params=start_pkgdata_filling(params,parser,filename_given,&comm)))
        {
            printf("Failed to parse pkg specification file!\n");
            goto err_end;
        }
        parser->uninit_parser(&parser);
    }
    else 
    {
        printf("WTF? fileversion should've been checked already!\n");
        goto err_end;
    }
    if(!params->pkg_size)
        params->pkg_size=1500;
    if(!nodaemon)
        daemon(1,1);
    rval=EthBombardier(params,&comm);

    if(0)
    {
err_end:
        rval=EXIT_FAILURE;
    }
    if(rval)
        printf("FAILURE\n");
    else
end:
        printf("SUCCESS\n");
    return rval;
}



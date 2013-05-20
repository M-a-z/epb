#include "epb_pcap_parser.h"
#include "epb_pcap_hdrs.h"
#include "epb_helpers.h"
#if 0
typedef struct SPcap_File_hdr
{
    unsigned int    magic_number;
    unsigned short  version_major;
    unsigned short  version_minor;
    int             zone;
    unsigned int    timestamp_acc;
    unsigned int    snaplen;
    unsigned int    net;
}SPcap_File_hdr;

typedef struct SPcap_Packet_hdr
{
    unsigned int    sec;
    unsigned int    micsec;
    unsigned int    caplen;
    unsigned int    origlen;
}SPcap_Packet_hdr;
#endif

static int parse_pdata_parse(SEpbPacketParser *_this, SEpbParams *params, SCommParams *comm);
static int parse_pdata_strip(SEpbPacketParser *_this, SEpbParams *params, SCommParams *comm);
static int parse_pdata(SEpbPacketParser *_this, SEpbParams *params, SCommParams *comm);
static int parse_phead_parse(SEpbPacketParser *_this,  SEpbParams *newpkg, SCommParams *comm);


static int parse_fhead(SEpbPacketParser *_this,FILE *pkgfile, SEpbParams *params, SCommParams *comm)
{
    SEpbPacketParserPCAP *_this_=(SEpbPacketParserPCAP *)_this;
    /* read file magic */
    /* check link layer type (ethernet = 1) */
    _this->fptr=pkgfile;
    if(1!=fread(&(_this_->filehdr),sizeof(SPcap_File_hdr),1,pkgfile))
    {
        printf("Failed to read pcap file header from file!\n");
        return -1;
    }
    if(_this_->filehdr.magic_number == 0xA1B2C3D4)
    {
        _this_->prepare32=&dummyswap32;
        _this_->prepare16=&dummyswap16;
    }
    else if(_this_->filehdr.magic_number == 0xD4C3B2A1)
    {
        _this_->prepare32=&swap32;
        _this_->prepare16=&swap16;
    }
    else
    {
        printf("Invalid file magic, is this really a valid PCAP file?\n");
        return -1;
    }
    if(_this_->prepare32(_this_->filehdr.net) != 1)
    {
        printf("Unknown underlying network type %u in pcap file!\n",_this_->prepare32(_this_->filehdr.net));
        return -1;
    }

    if(!(comm->operation & EPB_PARSER_OP_PARSE))
    {
        memcpy(comm->strip_file_ext,"pcap",5);
        _this_->operation_header_size=sizeof(SPcap_Packet_hdr);
        if(comm->operation & EPB_PARSER_OP_STRIP_DST_MAC)
            _this_->stripoffset=0;
        else if(comm->operation & EPB_PARSER_OP_STRIP_SRC_MAC)
            _this_->stripoffset=6;
        else
            _this_->stripoffset=12;
    }
     
    return 0;
}
static int parse_phead(SEpbPacketParser *_this,  SEpbParams *newpkg, SCommParams *comm)
{
    //SEpbPacketParserPCAP *_this_=(SEpbPacketParserPCAP *)_this;
    //???
    _this->parse_phead=&parse_phead_parse;
    return (*_this->parse_phead)(_this,newpkg,comm);
}
static int parse_phead_parse(SEpbPacketParser *_this,  SEpbParams *newpkg, SCommParams *comm)
{
    SEpbPacketParserPCAP *_this_=(SEpbPacketParserPCAP *)_this;
    unsigned long long int tstamp;
    if(1!=fread(&(_this_->pkghdr),sizeof(SPcap_Packet_hdr),1,_this->fptr))
    {
        if(feof(_this->fptr))
            return PARSER_READ_EOF;
        printf("Failed to read pcap packet header from file %s\n",comm->filename);
        return -1;
    }
    /* Compare origlen and actual len - if they do not match ... */
    if(_this_->pkghdr.origlen != _this_->pkghdr.caplen)
    {
        printf("ill sized packet! original packet len %u, captured packet len %u\n",_this_->prepare32(_this_->pkghdr.origlen),_this_->prepare32(_this_->pkghdr.caplen));
        return -1;
    }
    /* read timestamp and compare to previous if previous != 0 - set delay accordingly and store timestamp */
    tstamp=1000000ULL*(unsigned long long)_this_->prepare32(_this_->pkghdr.sec);
    tstamp+=(unsigned long long)_this_->prepare32(_this_->pkghdr.micsec);
    if(_this_->timestamp)
    {
        newpkg->startdelay=(unsigned) (tstamp-_this_->timestamp);
    }
    _this_->timestamp=tstamp;

    /* Store packet len */
    newpkg->pkg_size=_this_->prepare32(_this_->pkghdr.caplen)+_this_->operation_header_size; 
    return 0;
}

static void add_pkg_defs(SEpbPacketParser *_this,  SEpbParams *newpkg, SEpbParams *cmdlineopts)
{
    /* Allow overriding package interval from command line */
    /* Note, since *interval* in code relates to delay for repeated packetes, but with pcap files it really feels user-wise to be a
     * delay between packages read from file we need to set interval as startdelay so it affects to all (not repeated - which 
     * in pcap parser means nothing) packets.
     */
    if(cmdlineopts->interval)
        newpkg->startdelay=cmdlineopts->interval;
    newpkg->pkg_amnt=1;
    /*
    if((newpkg->use_realmac=cmdlineopts->use_realmac))
    {
        memcpy(&(newpkg->real_mac[0]),&(cmdlineopts->real_mac[0]),6);
    }
    */
}

//static int parse_pdata_strip(SEpbPacketParser *_this, SEpbParams *params)
static int parse_pdata_strip(SEpbPacketParser *_this, SEpbParams *params, SCommParams *comm)
{
    unsigned char *pkg=&(params->pkg[0]);
    int rval=0;
    SEpbPacketParserPCAP *_this_=(SEpbPacketParserPCAP *)_this;
    
    pkg=malloc(params->pkg_size-sizeof(SPcap_Packet_hdr));
    if(!pkg)
    {
        printf("Malloc FAILED!\n");
        return -1;
    }

    rval=fread(pkg,params->pkg_size-sizeof(SPcap_Packet_hdr),1,_this->fptr);
    if(rval!=1)
    {
        if(feof(_this->fptr))
            rval=PARSER_READ_EOF;
        rval=-1;
        goto out;
    }
    if(_this_->stripoffset+comm->stripcompsize>params->pkg_size-sizeof(SPcap_Packet_hdr))
    {
        params->pkg_size=0;
        goto out;
    }
#ifdef DEBUGPRINTS
    if(_this_stripoffset==0 || _this_->stripoffset=6)
        printf
        (
            "Comparing macs, pkg:stripmac\t%x:%x:%x:%x:%x:%x Vs %x:%x:%x:%x:%x:%x\n",
            (unsigned int)*(((char *)pkg)+_this_->stripoffset),
            (unsigned int)*(((char *)pkg)+_this_->stripoffset+1),
            (unsigned int)*(((char *)pkg)+_this_->stripoffset+2),
            (unsigned int)*(((char *)pkg)+_this_->stripoffset+3),
            (unsigned int)*(((char *)pkg)+_this_->stripoffset+4),
            (unsigned int)*(((char *)pkg)+_this_->stripoffset+5),
            (unsigned int)comm->stripcompdata[0],
            (unsigned int)comm->stripcompdata[1],
            (unsigned int)comm->stripcompdata[2],
            (unsigned int)comm->stripcompdata[3],
            (unsigned int)comm->stripcompdata[4],
            (unsigned int)comm->stripcompdata[5]
        );
#endif
    if(!memcmp(((char *)pkg)+_this_->stripoffset,comm->stripcompdata,comm->stripcompsize))
    {
#ifdef DEBUGPRINTS
        printf("Matcing pkg found!\n");
#endif
        memcpy(&(params->pkg[0]),&(_this_->pkghdr),sizeof(SPcap_Packet_hdr));
        memcpy(&(params->pkg[sizeof(SPcap_Packet_hdr)]),pkg,params->pkg_size-sizeof(SPcap_Packet_hdr));
        if(comm->use_realmac && params->pkg_size > 12)
            memcpy(&(pkg[sizeof(SPcap_Packet_hdr)+6]),comm->real_mac,6);
    }
    else
        params->pkg_size=0;
out:
    free(pkg);
    return 0;
}
void htonmac(unsigned char *mac)
{
    short one=1;
    unsigned char *tmp=(unsigned char *)&one;

    if(!*tmp)
        return;
    
#ifdef DEBUGPRINTS
    printf("mac before swap = %x:%x:%x:%x:%x:%x\n",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
#endif
    for(*tmp=0;*tmp<3;(*tmp)++)
    {
        *(tmp+1)=mac[5-(int)*tmp];
        mac[5-(int)*tmp]=mac[*tmp];
        mac[*tmp]=*(tmp+1);
    }
#ifdef DEBUGPRINTS
    printf("mac after swap = %x:%x:%x:%x:%x:%x\n",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
#endif
}

static int finalize(SEpbPacketParser *_this,SEpbParams *paramhead,SCommParams *comm)
{
    SEpbParams *tmp;
    SEpbPacketParserPCAP *_this_=(SEpbPacketParserPCAP*)_this;
    char *writeptr;
    comm->filesize=sizeof(SPcap_File_hdr);
    for(tmp=paramhead;tmp;tmp=tmp->next)
    {
        comm->filesize+=tmp->pkg_size;
    }
    comm->filedata=malloc(comm->filesize);
    writeptr=comm->filedata;
    if(comm->filedata && comm->filesize)
    {
        memcpy(comm->filedata,&(_this_->filehdr),sizeof(SPcap_File_hdr));
        writeptr+=sizeof(SPcap_File_hdr);
        for(tmp=paramhead->next;tmp;tmp=tmp->next)
        {
            memcpy(writeptr,&(tmp->pkg[0]),tmp->pkg_size);
            writeptr+=tmp->pkg_size;
        }
    }
    else
        return -1;
    return 0;
}
//static int parse_pdata(SEpbPacketParser *_this, SEpbParams *params)
static int parse_pdata(SEpbPacketParser *_this, SEpbParams *params, SCommParams *comm)
{
    if(comm->operation & EPB_PARSER_OP_PARSE)
        _this->parse_pdata=&parse_pdata_parse;
    else
        _this->parse_pdata=&parse_pdata_strip;
    return (*_this->parse_pdata)(_this,params,comm);
}

//static int parse_pdata_parse(SEpbPacketParser *_this, SEpbParams *params)
static int parse_pdata_parse(SEpbPacketParser *_this, SEpbParams *params, SCommParams *comm)
{
    /* read packetlen bytes and assume that's the packet */
    //SEpbPacketParserPCAP *_this_=(SEpbPacketParserPCAP *)_this;
    unsigned char *pkg=&(params->pkg[0]);
    int rval=0;
    
    rval=fread(pkg,params->pkg_size,1,_this->fptr);
    if(rval!=1)
    {
        if(feof(_this->fptr))
            return PARSER_READ_EOF;
        return -1;
    }
    
    if(comm->use_realmac && params->pkg_size > 12)
        memcpy(&(pkg[6]),comm->real_mac,6);
    return 0;
}

static void uninit_parser(SEpbPacketParser **_this_)
{
    if(!_this_)
        return;
    if(*_this_)
        free(*_this_);
    *_this_=NULL;
}

SEpbPacketParser *init_pcapfile_parser()
{
    SEpbPacketParserPCAP *_this;
    _this=calloc(1,sizeof(SEpbPacketParserPCAP));
    if(!_this)
    {
        printf("%s: calloc FAILED!\n",__FUNCTION__);
        return NULL;
    }
    _this->genparser.parsertype=2;
    _this->genparser.supported_operations= PCAP_PARSER_SUPP_OPS; 
    _this->genparser.finalize=&finalize;
    _this->genparser.parse_fhead=&parse_fhead;
    _this->genparser.parse_phead=&parse_phead;
    _this->genparser.add_pkg_defs=&add_pkg_defs;
    _this->genparser.parse_pdata=&parse_pdata;
    _this->genparser.uninit_parser=&uninit_parser;
    return (SEpbPacketParser *)_this;
}


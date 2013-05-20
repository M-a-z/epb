#include "epb_pcap_ng_parser.h"
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

typedef struct SPcapNgSecHdrBlock
{
    uint32_t block_type;
    uint32_t block_total_len;
    uint32_t byte_order_magic;
    uint16_t vermajor;
    uint16_t verminor;
    uint64_t section_len;
    uint32_t block_total_len2;
}SPcapNgSecHdrBlock;

typedef struct SPcapNgIfDescBlock
{
    uint32_t block_type;
    uint32_t block_total_len;
    uint16_t link_type;
    uint16_t reserved;
    uint32_t snaplen;
    uint32_t block_total_len2;
}SPcapNgIfDescBlock;

typedef struct SPcapNgEnchancedPacketBlock
{
    uint32_t block_type;
    uint32_t block_total_len;
    uint32_t interface_id;
    uint32_t timestamp_hi;
    uint32_t timestamp_lo;
    uint32_t cap_len;
    uint32_t packet_len;
}SPcapNgEnchancedPacketBlock;

typedef struct SPcapNgSimplePacketBlock
{
    uint32_t block_type;
    uint32_t block_total_len;
    uint32_t packet_len;
}SPcapNgSimplePacketBlock;


#endif

static int parse_pdata_parse(SEpbPacketParser *_this, SEpbParams *params, SCommParams *comm);
static int parse_pdata_strip(SEpbPacketParser *_this, SEpbParams *params, SCommParams *comm);
static int parse_pdata(SEpbPacketParser *_this, SEpbParams *params, SCommParams *comm);
static int parse_phead_parse(SEpbPacketParser *_this,  SEpbParams *newpkg, SCommParams *comm);


static int parse_fhead(SEpbPacketParser *_this,FILE *pkgfile, SEpbParams *params, SCommParams *comm)
{
    const uint32_t expmagic=0x0a0d0d0a;
    //SpcapNgBlockCommons com;
    SEpbPacketParserPCAPng *_this_=(SEpbPacketParserPCAPng *)_this;
    /* read file magic */
    /* check link layer type (ethernet = 1) */
    _this->fptr=pkgfile;

    if(1!=fread(&_this_->filehdr,sizeof(SPcapNgSecHdrBlock),1,pkgfile))
    {
        printf("Failed to read first section header from pcapng file!\n");
        return -1;
    }
    if(_this_->filehdr.block_type!= expmagic)
    {
        printf("magic 0x%08x, expected 0x%08x\n",_this_->filehdr.block_type,expmagic);
        printf("Invalid file type magic! is this really a valid PCAPng file?\n");
        return -1;
    }
    if(_this_->filehdr.byte_order_magic == 0x1A2B3C4D)
    {
        _this_->prepare32=&dummyswap32;
        _this_->prepare16=&dummyswap16;
    }
    else if(_this_->filehdr.byte_order_magic == 0x4D3C2B1A)
    {
        _this_->prepare32=&swap32;
        _this_->prepare16=&swap16;
    }
    else
    {
        printf("Invalid byte order magic 0x%08x, is this really a valid PCAPng file?\n",_this_->filehdr.byte_order_magic);
        return -1;
    }
    /* TODO: add reading interface header etc... */
/*
    if(_this_->prepare32(_this_->filehdr.net) != 1)
    {
        printf("Unknown underlying network type %u in pcap file!\n",_this_->prepare32(_this_->filehdr.net));
        return -1;
    }
*/
    /*
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
     */
    return 0;
}
static int parse_phead(SEpbPacketParser *_this,  SEpbParams *newpkg, SCommParams *comm)
{
    //SEpbPacketParserPCAPng *_this_=(SEpbPacketParserPCAPng *)_this;
    //???
    _this->parse_phead=&parse_phead_parse;
    return (*_this->parse_phead)(_this,newpkg,comm);
}
static int parse_phead_parse(SEpbPacketParser *_this,  SEpbParams *newpkg, SCommParams *comm)
{
    char *errchar;

    SEpbPacketParserPCAPng *_this_=(SEpbPacketParserPCAPng *)_this;
    unsigned long long int tstamp;
reread:
    errchar="Failed to read pcapng packet header from file!";
    if(1!=fread(&(_this_->bcom),sizeof(SpcapNgBlockCommons),1,_this->fptr))
        goto filereadfail_out; 
    _this_->bcom.block_type=_this_->prepare32(_this_->bcom.block_type);
    _this_->bcom.block_total_len=_this_->prepare32(_this_->bcom.block_total_len);

    if(6 == _this_->bcom.block_type)
    {
        SPcapNgEnchancedPacketBlock blk;
        errchar="Failed to read enchanced packet block header from file";
        if
        (
            1!=
            fread
                (
                    &(blk.interface_id),
                    sizeof
                    (
                        SPcapNgEnchancedPacketBlock
                    )
                    -
                    offsetof
                    (
                        SPcapNgEnchancedPacketBlock,interface_id
                    ),
                    1,
                    _this->fptr
                )
        )
            goto filereadfail_out;
        errchar="ill sized packet captured! original packet size != capture size";
        if(blk.cap_len!=blk.packet_len)
            goto filereadfail_out;
        errchar="looks like theres packets from multiple interfaces - aborting!\n";
        if(blk.interface_id)
            goto filereadfail_out;
        tstamp=(((uint64_t)(_this_->prepare32(blk.timestamp_hi)))<<32);
        tstamp|=((uint64_t)(_this_->prepare32(blk.timestamp_lo)));
        if(_this_->timestamp)
            newpkg->startdelay=(unsigned) (tstamp-_this_->timestamp);
        _this_->timestamp=tstamp;
        _this_->blockbottom=_this_->bcom.block_total_len-_this_->prepare32(blk.cap_len)-sizeof(SPcapNgEnchancedPacketBlock);
        newpkg->pkg_size=_this_->prepare32(blk.cap_len);

    }
    else if(3 == _this_->bcom.block_type )
    {
        uint32_t packet_len;
        errchar="Failed to read simple packet block header from file";
        if
        (
            1!=
            fread
                (
                    &packet_len,
                    sizeof(uint32_t),
                    1,
                    _this->fptr
                )
        )
            goto filereadfail_out;
        _this_->blockbottom=_this_->bcom.block_total_len-_this_->prepare32(packet_len)-12;
        newpkg->pkg_size=_this_->prepare32(packet_len);

    }
    else
    {
        printf("Skipping unknown block - type %u\n",_this_->bcom.block_type);
        if(fseek(_this->fptr, _this_->bcom.block_total_len-8, SEEK_CUR))
        {
            errchar="failed to skip unknown pcapNG header!";
            goto filereadfail_out;
        }
        goto reread;
    }

    if(0)
    {
filereadfail_out:
        if(feof(_this->fptr))
            return PARSER_READ_EOF;
       printf("ERROR: %s\n",errchar);
       return -1;
    }
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
#if 0
    unsigned char *pkg=&(params->pkg[0]);
    int rval=0;
    SEpbPacketParserPCAPng *_this_=(SEpbPacketParserPCAPng *)_this;
    
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
#endif
    return 0;
}
#if 0
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
#endif

static int finalize(SEpbPacketParser *_this,SEpbParams *paramhead,SCommParams *comm)
{
    SEpbParams *tmp;
    SEpbPacketParserPCAPng *_this_=(SEpbPacketParserPCAPng*)_this;
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
    uint32_t tmp;
    SEpbPacketParserPCAPng *_this_=(SEpbPacketParserPCAPng *)_this;
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
    /* read the total block size from the end of block */
    printf("blockbottom set to %u\n",_this_->blockbottom);
    fseek(_this->fptr,_this_->blockbottom-4,SEEK_CUR);
    rval=fread(&tmp,sizeof(tmp),1,_this->fptr);
    printf("total block size at the end of block: %u\n",_this_->prepare32(tmp));
    if(rval!=1)
    {
        if(feof(_this->fptr))
            return PARSER_READ_EOF;
        return -1;
    }
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

SEpbPacketParser *init_pcapngfile_parser()
{
    SEpbPacketParserPCAPng *_this;
    _this=calloc(1,sizeof(SEpbPacketParserPCAPng));
    if(!_this)
    {
        printf("%s: calloc FAILED!\n",__FUNCTION__);
        return NULL;
    }
    _this->genparser.parsertype=EPB_FILE_PARSER_PCAPNG;
    _this->genparser.supported_operations= PCAP_NG_PARSER_SUPP_OPS; 
    _this->genparser.finalize=&finalize;
    _this->genparser.parse_fhead=&parse_fhead;
    _this->genparser.parse_phead=&parse_phead;
    _this->genparser.add_pkg_defs=&add_pkg_defs;
    _this->genparser.parse_pdata=&parse_pdata;
    _this->genparser.uninit_parser=&uninit_parser;
    return (SEpbPacketParser *)_this;
}


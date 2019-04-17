#include "epb_netmon_parser.h"
#include "epb_helpers.h"

static int G_swap_netmon=0;

#define NETMON_READ_32(value) ((G_swap_netmon)?swap32(value):(value))
#define NETMON_READ_16(value) ((G_swap_netmon)?swap16(value):(value))

static int parse_phead_netmon1(SEpbPacketParser *_this,  SEpbParams *newpkg, SCommParams *comm);
static int parse_phead_netmon2(SEpbPacketParser *_this,  SEpbParams *newpkg, SCommParams *comm);
//static int parse_phead_netmon1(SEpbPacketParser *_this,  SEpbParams *newpkg);
//static int parse_phead_netmon2(SEpbPacketParser *_this,  SEpbParams *newpkg);

//static int parse_fhead(SEpbPacketParser *_this, FILE *pkgfile)
static int parse_fhead(SEpbPacketParser *_this,FILE *pkgfile, SEpbParams *params, SCommParams *comm)
{
    unsigned short one=1;
    unsigned char *two=(unsigned char *)&one;
    if(!*two)
    {
        G_swap_netmon=1;
    }
    SEpbPacketParserNETMON *_this_=(SEpbPacketParserNETMON *)_this;
    unsigned frametablelen;
    SNetmon_File_hdr filehdr;
    int i;
    /* read file magic */
    /* check link layer type (ethernet = 1) */
    _this->fptr=pkgfile;
    if(1!=fread(&filehdr,sizeof(SNetmon_File_hdr),1,pkgfile))
    {
        printf("Failed to read netmon file header from file!\n");
        return -1;
    }
    if(filehdr.magic_number == *(unsigned int *)netmon1_magic)
    {
        _this->parse_phead=&parse_phead_netmon1;
    }
    else if(filehdr.magic_number == *(unsigned int *)netmon2_magic)
    {
        _this->parse_phead=&parse_phead_netmon2;
    }
    else
    {
        printf("Invalid file magic, is this really a valid NETMON file?\n");
        return -1;
    }
    if(NETMON_READ_16(filehdr.network) != 1)
    {
        printf("Unknown underlying network type %hu in netmon file!\n",NETMON_READ_16(filehdr.network));
        return -1;
    }
    frametablelen=NETMON_READ_32(filehdr.frametablelength);
    _this_->captured_frames=frametablelen/4;
#ifdef DEBUGPRINTS
    printf
    (
        "Going to frame table offset (%u), and reading frame table (size %u)\n",
        NETMON_READ_32(filehdr.frametableoffset),
        frametablelen
    );
#endif

     if(fseek(pkgfile,NETMON_READ_32(filehdr.frametableoffset),SEEK_SET))
    {
        printf("Failed to read netmon header padding bytes\n");
        return -1;
    }
    _this_->ftable=malloc(frametablelen);
    if(!_this_->ftable)
    {
        printf("Failed to allocate %u bytes for netmon frame table\n",frametablelen);

    }
    if(1!=fread(_this_->ftable,frametablelen,1,pkgfile))
    {
        printf("Failed to read frame table!\n");
        return -1;
    }
    for(i=0;i<_this_->captured_frames;i++)
    {
        _this_->ftable[i]=NETMON_READ_32(_this_->ftable[i]);
    }
    _this_->curr_frame=0;
    return 0;
}

//static int parse_phead_netmon2(SEpbPacketParser *_this,  SEpbParams *newpkg)
static int parse_phead_netmon2(SEpbPacketParser *_this,  SEpbParams *newpkg, SCommParams *comm)
{
    SEpbPacketParserNETMON *_this_=(SEpbPacketParserNETMON *)_this;
    SNetmon_2_Packet_hdr pkghdr;
    unsigned long long int tstamp;

    /* last record should've been read by now ? */
    if(_this_->curr_frame>=_this_->captured_frames)
        return PARSER_READ_EOF;

    if(fseek(_this->fptr,_this_->ftable[_this_->curr_frame],SEEK_SET))
    {
        printf("Failed to seek frame %u from fileoffset %u\n",_this_->curr_frame,_this_->ftable[_this_->curr_frame]);
        return -1;
    }
    if(1!=fread(&pkghdr,sizeof(SNetmon_2_Packet_hdr),1,_this->fptr))
    {
        if(feof(_this->fptr))
            return PARSER_READ_EOF;
        printf("Failed to read netmon packet header from file %s\n",comm->filename);
        return -1;
    }
    _this_->curr_frame++;
    /* Compare origlen and actual len - if they do not match ... */
    if(pkghdr.origlen != pkghdr.caplen)
    {
        printf("ill sized packet! original packet len %u, captured packet len %u\n",NETMON_READ_32(pkghdr.origlen),NETMON_READ_32(pkghdr.caplen));
        return -1;
    }
    /* read timestamp and compare to previous if previous != 0 - set delay accordingly and store timestamp */
    tstamp=((unsigned long long)NETMON_READ_32(pkghdr.ts_delta_hi));
    tstamp<<=32;
    tstamp+=((unsigned long long)NETMON_READ_32(pkghdr.ts_delta_lo));
    if(_this_->timestamp)
    {
        newpkg->startdelay=(unsigned) (tstamp-_this_->timestamp);
    }
    _this_->timestamp=tstamp;

    /* Store packet len */
    newpkg->pkg_size=NETMON_READ_32(pkghdr.caplen); 

#ifdef DEBUGPRINTS
    printf("Set real package size to %u (read from netmon)\n",newpkg->pkg_size);
#endif
    return 0;
}



//static int parse_phead_netmon1(SEpbPacketParser *_this,  SEpbParams *newpkg)
static int parse_phead_netmon1(SEpbPacketParser *_this,  SEpbParams *newpkg, SCommParams *comm)
{
    SEpbPacketParserNETMON *_this_=(SEpbPacketParserNETMON *)_this;
    SNetmon_1_Packet_hdr pkghdr;
    unsigned long long int tstamp;

    /* last record should've been read by now ? */
    if(_this_->curr_frame>=_this_->captured_frames)
        return PARSER_READ_EOF;

    if(fseek(_this->fptr,_this_->ftable[_this_->curr_frame],SEEK_SET))
    {
        printf("Failed to seek frame %u from fileoffset %u\n",_this_->curr_frame,_this_->ftable[_this_->curr_frame]);
        return -1;
    }
    if(1!=fread(&pkghdr,sizeof(SNetmon_1_Packet_hdr),1,_this->fptr))
    {
        if(feof(_this->fptr))
            return PARSER_READ_EOF;
        printf("Failed to read netmon packet header from file %s\n",comm->filename);
        return -1;
    }
    _this_->curr_frame++;
    /* Compare origlen and actual len - if they do not match ... */
    if(pkghdr.origlen != pkghdr.caplen)
    {
        printf("ill sized packet! original packet len %hu, captured packet len %hu\n",NETMON_READ_16(pkghdr.origlen),NETMON_READ_16(pkghdr.caplen));
        return -1;
    }
    /* read timestamp and compare to previous if previous != 0 - set delay accordingly and store timestamp */
    tstamp=1000ULL*(unsigned long long)NETMON_READ_32(pkghdr.ts_delta);
//    tstamp+=(unsigned long long)NETMON_READ_32(pkghdr.micsec);
    if(_this_->timestamp)
    {
        newpkg->startdelay=(unsigned) (tstamp-_this_->timestamp);
    }
    _this_->timestamp=tstamp;

    /* Store packet len */
    newpkg->pkg_size=(unsigned)NETMON_READ_16(pkghdr.caplen); 
#ifdef DEBUGPRINTS
    printf("Set real package size to %u (read from netmon)\n",newpkg->pkg_size);
#endif
    return 0;
}

static void add_pkg_defs(SEpbPacketParser *_this,  SEpbParams *newpkg, SEpbParams *cmdlineopts)
{
    /* Allow overriding package interval from command line */
    /* Note, since *interval* in code relates to delay for repeated packetes, but with netmon files it really feels user-wise to be a
     * delay between packages read from file we need to set interval as startdelay so it affects to all (not repeated - which 
     * in netmon parser means nothing) packets.
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

//static int parse_pdata(SEpbPacketParser *_this, SEpbParams *params)
static int parse_pdata(SEpbPacketParser *_this, SEpbParams *params, SCommParams *comm)
{
    /* read packetlen bytes and assume that's the packet */
    //SEpbPacketParserNETMON *_this_=(SEpbPacketParserNETMON *)_this;
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
    {
        if((*(SEpbPacketParserNETMON **)_this_)->ftable)
            free((*(SEpbPacketParserNETMON **)_this_)->ftable);
        free(*_this_);
    }
    *_this_=NULL;
}

SEpbPacketParser *init_netmonfile_parser()
{
    SEpbPacketParserNETMON *_this;
    _this=calloc(1,sizeof(SEpbPacketParserNETMON));
    if(!_this)
    {
        printf("%s: calloc FAILED!\n",__FUNCTION__);
        return NULL;
    }
    _this->genparser.parsertype=2;
    _this->genparser.supported_operations=EPB_PARSER_OP_PARSE;
    _this->genparser.parse_fhead=&parse_fhead;
    _this->genparser.add_pkg_defs=&add_pkg_defs;
    _this->genparser.parse_pdata=&parse_pdata;
    _this->genparser.uninit_parser=&uninit_parser;
    return (SEpbPacketParser *)_this;
}


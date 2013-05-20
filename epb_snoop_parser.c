#include "epb_snoop_parser.h"
#include <stdio.h>
#include <stdlib.h>
//#include "epb_pcap_hdrs.h"
#include "epb_helpers.h"
static int parse_pdata_parse(SEpbPacketParser *_this, SEpbParams *params, SCommParams *comm);

static int add_piece_for_stripper(SEpbPacketParserSNOOP *_this_,void *piece,size_t size)
{
    SnoopStripperResults *newres;
    newres=malloc(sizeof(SnoopStripperResults)+size-1);
    if(!newres)
    {
        printf("Malloc FAILED!\n");
        return -1;
    } 
    newres->next=_this_->resulthead->next;
    newres->thispiecesize=size;
    memcpy(&(newres->data[0]),piece,size);
    _this_->resulthead->next=newres;
    return 0;
}

static int parse_fhead(SEpbPacketParser *_this,FILE *pkgfile, SEpbParams *params, SCommParams *comm)
{
    SEpbPacketParserSNOOP *_this_=(SEpbPacketParserSNOOP *)_this;
    SSnoop_File_hdr filehdr;
    char snoopmagic[8]={'s','n','o','o','p','\0','\0','\0'};
    /* read file magic */
    /* check link layer type (ethernet = 1) */
    _this->fptr=pkgfile;
    if(1!=fread(&filehdr,sizeof(SSnoop_File_hdr),1,pkgfile))
    {
        printf("Failed to read snoop file header from file!\n");
        return -1;
    }
    if(filehdr.magic_number !=  *(unsigned long long *)snoopmagic)
    {
        printf("Invalid file magic in record file, are you sure this is a snoop capture?\n");
        return -1;
    }
    
    if(ntohl(filehdr.version) != 2)
    {
        printf("epb supports only snoop file version 2, record appears to be version %u\n",ntohl(filehdr.version));
        return -1;
    }
    if(ntohl(filehdr.net)!=4)
    {
        printf("Unknown underlying network type %u in snoop file!\n",ntohl(filehdr.net));
        return -1;
    }
    if(!(comm->operation& EPB_PARSER_OP_PARSE))
    {
        memcpy(comm->strip_file_ext,"snoop",6);
        _this_->resulthead=malloc(sizeof(SnoopStripperResults)+sizeof(SSnoop_File_hdr)-1);
       if(!_this_->resulthead)
       {
          printf("Malloc FAILED!\n");
          return -1;
       } 
       _this_->resulthead->next=NULL;
       _this_->resulthead->thispiecesize=sizeof(SSnoop_File_hdr);
       memcpy(&(_this_->resulthead->data[0]),&filehdr,sizeof(SSnoop_File_hdr));
       if(comm->operation&EPB_PARSER_OP_STRIP_DST_MAC)
           _this_->compoffset=0;
       else if(comm->operation&EPB_PARSER_OP_STRIP_SRC_MAC)
           _this_->compoffset=6;
       else
           _this_->compoffset=12;
    }
    return 0;
}

//static int parse_phead(SEpbPacketParser *_this,  SEpbParams *newpkg)
static int parse_phead(SEpbPacketParser *_this,  SEpbParams *newpkg, SCommParams *comm)
{
    SEpbPacketParserSNOOP *_this_=(SEpbPacketParserSNOOP *)_this;
//    SSnoop_Packet_hdr pkghdr;
    unsigned long long int tstamp;
    if(1!=fread(&_this_->pkghdr,sizeof(SSnoop_Packet_hdr),1,_this->fptr))
    {
        if(feof(_this->fptr))
            return PARSER_READ_EOF;
        printf("Failed to read snoop packet header from file %s\n",comm->filename);
        return -1;
    }
    /* Compare origlen and actual len - if they do not match ... */
    if
    (
        _this_->pkghdr.origlen != _this_->pkghdr.caplen || 
        (newpkg->pkg_size=ntohl(_this_->pkghdr.caplen)) > 
        (_this_->recordlen=ntohl(_this_->pkghdr.recordlen))
    )
    {
        printf
        (
            "ill sized packet! original packet len %u, captured packet len %u, record len %u\n",
            ntohl(_this_->pkghdr.origlen),
            ntohl(_this_->pkghdr.caplen),
            ntohl(_this_->pkghdr.recordlen)
        );
        return -1;
    }
    /* read timestamp and compare to previous if previous != 0 - set delay accordingly and store timestamp */
    tstamp=1000000ULL*(unsigned long long)ntohl(_this_->pkghdr.secs);
    tstamp+=(unsigned long long)ntohl(_this_->pkghdr.usecs);
    if(_this_->timestamp)
    {
        newpkg->startdelay=(unsigned) (tstamp-_this_->timestamp);
    }
    _this_->timestamp=tstamp;

    /* Store packet len */
#ifdef DEBUGPRINTS
    printf("Set real package size to %u (read from snoop)\n",newpkg->pkg_size);
#endif
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
    if((comm->use_realmac=cmdlineopts->use_realmac))
    {
        memcpy(&(newpkg->real_mac[0]),&(cmdlineopts->real_mac[0]),6);
    }
    */
}

//static int parse_pdata(SEpbPacketParser *_this, SEpbParams *params)
static int parse_pdata_strip(SEpbPacketParser *_this, SEpbParams *params, SCommParams *comm)
{
    /* read packetlen bytes and assume that's the packet */
    SEpbPacketParserSNOOP *_this_=(SEpbPacketParserSNOOP *)_this;
    int rval;
    char *data;
    
    if((rval=parse_pdata_parse(_this,params, comm)))
        return rval;
    if(!memcmp( &(params->pkg[ _this_->compoffset ]),comm->stripcompdata,comm->stripcompsize))
    {
        data=malloc(/* params->pkg_size */ _this_->recordlen);
        if(!data)
        {
            printf("malloc FAILED!\n");
            return -1;
        }
        memcpy(data,&(_this_->pkghdr),sizeof(SSnoop_Packet_hdr));
        memcpy(&(data[sizeof(SSnoop_Packet_hdr)]),&(params->pkg[0]),params->pkg_size);
        if(add_piece_for_stripper(_this_,data,_this_->recordlen))
        {
            printf("Failed to add stripped data to list!\n");
            return -1;
        }
    }
    return 0;
}

static int finalize(SEpbPacketParser *_this,SEpbParams *paramhead,SCommParams *comm)
{
    SEpbPacketParserSNOOP *_this_=(SEpbPacketParserSNOOP *)_this;
    SnoopStripperResults *tmp;
    unsigned offset=0;
    
    for(tmp=_this_->resulthead;tmp;tmp=tmp->next)
        comm->filesize+=tmp->thispiecesize;
    comm->filedata=malloc(comm->filesize);
    if(!comm->filedata)
    {
        printf("malloc FAILED!\n");
        return -1;
    }
    for(tmp=_this_->resulthead;tmp;tmp=tmp->next)
    {
        memcpy(((char *)comm->filedata)+offset,tmp->data,tmp->thispiecesize);
        offset+=tmp->thispiecesize;
    }
    return 0;
}
static int parse_pdata_parse(SEpbPacketParser *_this, SEpbParams *params, SCommParams *comm)
{
    /* read packetlen bytes and assume that's the packet */
    SEpbPacketParserSNOOP *_this_=(SEpbPacketParserSNOOP *)_this;
    unsigned char *pkg=&(params->pkg[0]);
    int rval=0;
    rval=fread(pkg,params->pkg_size,1,_this->fptr);
    if(rval!=1)
    {
        if(feof(_this->fptr))
            return PARSER_READ_EOF;
        return -1;
    }

#ifdef DEBUGPRINTS
    printf
    (
        "padding for record: %lu, current fpos %lu\n",
        _this_->recordlen - params->pkg_size- sizeof(SSnoop_Packet_hdr),
        ftell(_this->fptr)
    );
#endif
    /* bypass padding */
    if
    (
        fseek
        (
            _this->fptr,
            _this_->recordlen - params->pkg_size - sizeof(SSnoop_Packet_hdr),
            SEEK_CUR
        )
    )
    {
        int err=errno;
        printf("fseek failed when bypassing record padding! (%s)\n",strerror(err));
        return -1;
    }

#ifdef DEBUGPRINTS
    printf("position after readin padding: %lu\n",ftell(_this->fptr));
#endif
    if(comm->use_realmac && params->pkg_size > 12)
        memcpy(&(pkg[6]),comm->real_mac,6);
    return 0;
}
static int parse_pdata(SEpbPacketParser *_this, SEpbParams *params, SCommParams *comm)
{
    if(comm->operation & EPB_PARSER_OP_PARSE)
        _this->parse_pdata=&parse_pdata_parse;
    else
        _this->parse_pdata=&parse_pdata_strip;
    return (*_this->parse_pdata)(_this, params, comm);
}

static void uninit_parser(SEpbPacketParser **_this_)
{
    if(!_this_)
        return;
    if(*_this_)
        free(*_this_);
    *_this_=NULL;
}

SEpbPacketParser *init_snoopfile_parser()
{
    SEpbPacketParserSNOOP *_this;
    _this=calloc(1,sizeof(SEpbPacketParserSNOOP));
    if(!_this)
    {
        printf("%s: calloc FAILED!\n",__FUNCTION__);
        return NULL;
    }
    _this->genparser.parsertype=3;
    _this->genparser.supported_operations=(EPB_PARSER_OP_PARSE | EPB_PARSER_OP_STRIP_DST_MAC | EPB_PARSER_OP_STRIP_SRC_MAC | EPB_PARSER_OP_STRIP_ETHER_TYPE );
    _this->genparser.finalize=&finalize;
    _this->genparser.parse_fhead=&parse_fhead;
    _this->genparser.parse_phead=&parse_phead;
    _this->genparser.add_pkg_defs=&add_pkg_defs;
    _this->genparser.parse_pdata=&parse_pdata;
    _this->genparser.uninit_parser=&uninit_parser;
    return (SEpbPacketParser *)_this;
}


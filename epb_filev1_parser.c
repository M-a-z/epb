#include "epb_filev1_parser.h"
#include "epb_helpers.h"

//static int parse_fhead(SEpbPacketParser *_this, FILE *pkgfile)
static int parse_fhead(SEpbPacketParser *_this,FILE *pkgfile, SEpbParams *params, SCommParams *comm)
{
    (void) _this;
    _this->fptr=pkgfile;
    return 0;
}

//static int parse_phead(SEpbPacketParser *_this,  SEpbParams *newpkg)
static int parse_phead(SEpbPacketParser *_this,  SEpbParams *newpkg, SCommParams *comm)
{
    (void) newpkg;
    if( ((SEpbPacketParserV1*)_this)->eof)
        return PARSER_READ_EOF;
    return 0;
}

static void add_pkg_defs(SEpbPacketParser *_this,  SEpbParams *newpkg, SEpbParams *cmdlineopts)
{
    memcpy(newpkg,cmdlineopts,sizeof(SEpbParams));
    /*
    memset(params,0,sizeof(SEpbParams));
    params->pkg_amnt=1;
    params->startdelay=0;
    params->interval=1000000;
    */
}

//static int parse_pdata(SEpbPacketParser *_this, SEpbParams *params)
static int parse_pdata(SEpbPacketParser *_this, SEpbParams *params, SCommParams *comm)
{
    SEpbPacketParserV1 *_this_=(SEpbPacketParserV1 *)_this;
    unsigned char *pkg=&(params->pkg[0]);
    int rval=0;
    char *line;
    int macadded=0;
    SEpbIpPkg *ip_pkg;
    unsigned int lineno;
    unsigned int vartype;
    unsigned long long int var;
    char varsign;
    size_t pkgoffset=0;
    unsigned int *pkgsize=&(params->pkg_size);
    
    for(lineno=1;;lineno++)
    {
        int scanned;
        scanned=fscanf(_this->fptr,"#%m[^\n]\n",&line);
        if(scanned>0)
        {
#ifdef DEBUGPRINTS
            printf("Read comment '%s'\n",line);
#endif
            free(line);
            continue;
        }
        else if(EOF==scanned)
        {
            /*
            int err=errno;
            if(err)
                printf("file (%s) fucked up, %d,%s\n",comm->filename,err,strerror(err));
                rval=PARSER_READ_EOF;
                */
                _this_->eof=1;
            break;
        }
#ifdef DEBUGPRINTS
        else
            printf("NoComments\n");
#endif

        scanned=fscanf(_this->fptr,"%c%u:%m[^\n]\n",&varsign,&vartype,&line);
        if(scanned>0)
        {
            char *foo;
            if(scanned != 3)
            {
                printf("Invalid configline: %s:%u\n",comm->filename,lineno);
                return -1;
            }
#ifdef DEBUGPRINTS
            printf("read %c%u:%s\n",varsign,vartype,line);
#endif
            line=trimline(line);
            var=strtoll(line,&foo,0);
            if(NULL==line || '\0'!=*foo)
            {
                printf("Invalid value (%s) at %s:%u\n",(NULL==line)?"NULL":line,comm->filename,lineno);
                return -1;
            }
            free(line);

            /* add to struct */
            if(varsign!='u' && varsign!='i')
            {
                printf
                (
                    "Invalid variable sign (%c) in pkgfile %s line %u\n",
                    varsign,
                    comm->filename,
                    lineno
                );
                return -1;
            }
            if(*pkgsize<pkgoffset+(vartype/8))
            {
                printf("Looks like there's too much data in pkg file %s, given pkg size %u\n",comm->filename,*pkgsize);
                return -1;
            }

            switch(vartype)
            {

                case 8:
                {
                    unsigned char utmpchar;
                    char tmpchar;
                    utmpchar=(unsigned char)var;
                    tmpchar=(char)var;
                    memcpy( ( (char *)&(pkg[0])) + pkgoffset,(varsign=='u')?(char *)&utmpchar:(char *)&tmpchar,vartype/8);
                    break;
                }
                case 16:
                {
                    unsigned short utmpchar;
                    short tmpchar;
                    if(do_htons)
                    {
                        utmpchar=htons((unsigned short)var);
                        tmpchar=htons((short)var);
                    }
                    else
                    {
                        utmpchar=(unsigned short)var;
                        tmpchar=(short)var;
                    }
                    memcpy( ( (char *)&(pkg[0])) + pkgoffset,(varsign=='u')?(char *)&utmpchar:(char *)&tmpchar,vartype/8);
                    break;
                }
                case 32:
                {
                    unsigned int utmpchar;
                    int tmpchar;
                    if(do_htons)
                    {
                        utmpchar=htonl((unsigned int)var);
                        tmpchar=htonl((int)var);
                    }
                    else
                    {
                        utmpchar=(unsigned int)var;
                        tmpchar=(int)var;
                    }
                    memcpy( ( (char *)&(pkg[0])) + pkgoffset,(varsign=='u')?(char *)&utmpchar:(char *)&tmpchar,vartype/8);
                    break;
                }
                case 64:
                {
                    unsigned long long int utmpchar;
                    long long int tmpchar;
                    if(do_htons)
                    {
                        utmpchar=hotonlonglongloppi((unsigned long long int)var);
                        tmpchar=(long long int)hotonlonglongloppi((unsigned long long int)var);
                    }
                    else
                    {
                        utmpchar=(unsigned long long int)var;
                        tmpchar=(unsigned long long int)var;
                    }            
                    memcpy( ( (char *)&(pkg[0])) + pkgoffset,(varsign=='u')?(char *)&utmpchar:(char *)&tmpchar,vartype/8);
                    break;
                }
                default:
                    printf
                    (
                        "Invalid variable type %u in cfgfile '%s':%u. Supported 8,16,32 and 64 bits\n",
                        vartype,
                        comm->filename,
                        lineno
                    );
                    return -1;
                    break;
            }
            pkgoffset+=(vartype/8);
            if(comm->use_realmac && 6==pkgoffset)
            {
                memcpy( ( (char *)&(pkg[0])) + pkgoffset,comm->real_mac,6);
                pkgoffset+=6;
                macadded=1;
            }
            continue;
        }
        if(EOF == scanned)
        {
           //     rval=PARSER_READ_EOF;
                _this_->eof=1;
            break;
        }
    }    
    if(comm->use_realmac && !macadded )
    {
        if(*pkgsize<pkgoffset+6)
        {
            printf("Looks like there's too much data in pkg file %s, given pkg size %u - can't add srcmac\n",comm->filename,*pkgsize);
            return -1;
        }
        printf("WARNING packagefile did not contain 6 char wide walue (src mac) at start => forceinserting real mac\n");
        memmove( (((char *)&(pkg[0]))+12),(((char *)&(pkg[0]))+6),pkgoffset-6);
        memcpy((((char *)&(pkg[0]))+6),comm->real_mac,6);
    }
    ip_pkg=(SEpbIpPkg *)&(pkg[0]);
#ifdef DEBUGPRINTS
    printf("IP hdr ether type %hx\n",ip_pkg->eth_hdr.ether_type);
#endif
    if( ntohs(ip_pkg->eth_hdr.ether_type)==0x8100 ) 
    {
#ifdef DEBUGPRINTS
        printf("VLAN packet => adjusting packet start with 4 bytes\n");
#endif
        ip_pkg=(SEpbIpPkg *)&(pkg[4]);
#ifdef DEBUGPRINTS
        printf("ethertype now %hu\n",ip_pkg->eth_hdr.ether_type);
#endif
    }

    if
    ( 
        fillcsum &&
        ntohs(ip_pkg->eth_hdr.ether_type)==0x0800 &&
        0 == ip_pkg->ip_hdr.checksum
    )
    {
        unsigned short chksum;
        chksum=check_my_sum((unsigned short *)&(ip_pkg->ip_hdr),(size_t)((int)(ip_pkg->ip_hdr.ip_vhl&0x0F))*4);
        ip_pkg->ip_hdr.checksum=chksum;
    }
    *pkgsize=pkgoffset;
    return rval;
}

static void uninit_parser(SEpbPacketParser **_this_)
{
    if(!_this_)
        return;
    if(*_this_)
        free(*_this_);
    *_this_=NULL;
}

SEpbPacketParser *init_epbfile_1_parser()
{
    SEpbPacketParserV1 *_this;
    _this=calloc(1,sizeof(SEpbPacketParserV1));
    if(!_this)
    {
        printf("%s: calloc FAILED!\n",__FUNCTION__);
        return NULL;
    }
    _this->genparser.parsertype=0;
    _this->genparser.supported_operations=EPB_PARSER_OP_PARSE;
    _this->genparser.parse_fhead=&parse_fhead;
    _this->genparser.parse_phead=&parse_phead;
    _this->genparser.add_pkg_defs=&add_pkg_defs;
    _this->genparser.parse_pdata=&parse_pdata;
    _this->genparser.uninit_parser=&uninit_parser;
    return (SEpbPacketParser *)_this;
}


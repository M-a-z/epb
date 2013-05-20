#include "epb_helpers.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static void mva_htonll(unsigned long long *num)
{
    short one=1;
    char *two=(char *)&one;
    if(!*two)
        return;
    two++;
    for(one=0;*(char*)&one<4;one++)
    {
        *two=((char *)num)[7-*(char*)&one];
        ((char *)num)[7-*(char*)&one]=((char *)num)[(int)*(char*)&one];
        ((char *)num)[(int)*(char*)&one]=*two;
    }
}

unsigned long long int hotonlonglongloppi(unsigned long long int value)
{
    unsigned long long int tmp=value;
    mva_htonll(&tmp);
    return tmp;
}

unsigned short check_my_sum(unsigned short *buf, size_t len)
{
    unsigned long sum;
    int padding_needed;
    
    padding_needed=len%2;
    for(sum=0;len>1;len-=2)
    {
        sum+=*buf++;
    }
    if(padding_needed)
        sum+=( (((short int)*(char*)buf)<<8)&0xFF00);
    sum=(sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return ~sum;
}




int argchk(char *arg, unsigned long int lower, unsigned int upper, unsigned long int *value)
{
    char *chkptr;
    unsigned long int retval = 0;
    *value=0;
    if(NULL==arg)
    {
        printf("Non numeric arg!\n");
        return -1;
    }
    retval=strtoul(arg,&chkptr,0);
    if(*chkptr!='\0')
    {
        printf("Non numeric arg!\n");
        return -1;
    }
    if(retval>upper || retval < lower)
    {
        printf("Value %lx not in allowed range!\n",retval);
        return -1;
    }
    *value=retval;
    return 0;

}


char *trimline(char *line)
{
    int linelen;
    if(NULL==line)
        return NULL;
    linelen=strlen(line);
    for(;linelen-1>0 && line[linelen-1] == ' ';linelen--)
    {
        line[linelen-1]='\0';
    }
    for(;linelen-1>0 && line[0] == ' ';linelen--)
    {
        line+=1;
    }
    return line;
}

unsigned swap32(unsigned swapme)
{
    unsigned rval;
    unsigned char *tmp=(unsigned char *)&swapme;
    unsigned char *tmp2=(unsigned char *)&rval;
    tmp2[0]=tmp[3];
    tmp2[1]=tmp[2];
    tmp2[2]=tmp[1];
    tmp2[3]=tmp[0];
    return rval;
}
unsigned short swap16(unsigned short swapme)
{
    unsigned short rval;
    unsigned char *tmp=(unsigned char *)&swapme;
    unsigned char *tmp2=(unsigned char *)&rval;

    tmp2[1]=tmp[0];
    tmp2[0]=tmp[1];
    return rval;
}


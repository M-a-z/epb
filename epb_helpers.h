#ifndef EPB_PCAP_HELPERS_H
#define EPB_HELPERS_H
#include <stddef.h>


unsigned swap32(unsigned swapme);
unsigned short swap16(unsigned short swapme);
int argchk(char *arg, unsigned long int lower, unsigned int upper, unsigned long int *value);
char *trimline(char *line);
unsigned long long int hotonlonglongloppi(unsigned long long int value);
unsigned short check_my_sum(unsigned short *buf, size_t len);


#endif

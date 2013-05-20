#ifndef EPB_PCAP_HDRS_H
#define EPB_PCAP_HDRS_H
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

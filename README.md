# epb(8) - Ethernet Package Bombardier

v1.6, 18 July 2012

```
ebp  [ -SHvhwecm? ] [ .B-f  filename ] [ -n  interface ] [ -t  target ] [ -s  size ] [ -j -i -u  interval ] [ -d  delay ] [ -a  pkgamount ] [ -F fileversion ] [ -C  mac ] [ -T  mac ] [ -E ethertype ]
```


# Description

**ebp**(8) is a package sender allowing you to send tailored packages over network. This is usefull when testing different ARP handlings, iptables/arptables rules, routings, new protocols and so on. Originally epb was intended just to be a simple tool for packet crafting. Packages were specified in a human readable text file which was read and packages were then spilled to given network interface. This is still the main functionality but nowadays epb can also be used to replay previously captured data. **epb**(8) allows specifying whole packet starting from ethernet header. As a convenience feature the epb detects IPv4 ethernet type, and then checks if the IP-header's checksum field is filled. If IPv4 checksum is left empty, then checksum is calculated and filled before sending the packet.

Epb can read captured data dumps stored in **pcap**, snoop .cap or .pcapng files. See **-F** switch. **pcap and pcapng** (libpcap and pcap next generation) format is used by many tools like wireshark and tcpdump.  Snoop is a packet sniffer included in SUN, and Windows netmon sniffer uses .cap format. Currently epb supports onĺy netmon version 1 and 2 formats. When captured traces are sent, epb does sending of data as it is in capture files, no checksum filling or endianess conversions are supported.

Current epb version also supports stripping packets from pcap and snoop files based on ethernet header fields. This way epb can be used to strip packages targeted to certain destination mac addres, packages coming from certain source mac address, or packages having certain ether type (for example only IP packages). Epb then creates a new pcap/snoop trace file containing only these packages, and this file can then be sent via epb.

Captured pcap, pcapng snoop and netmon data can now be further edited before sending it. epb 1.6 development version contains 
**-H**
flag which makes epb to convert given trace into human readable and editable epb file 2 format. This file can then be modified using text editor like
**vim**
(1) and used to send the packets.

# Options


* **-H --humanreadable**  
  Makes epb to convert file specified with 
  **-f**
  and 
  **-F**
  flags to human readable and editable epb version 2 format.
* **-E --strip-ether-type**  
  followed by 16 bit ether type value (see ether type field in ethernet header). When epb is started with this flag, it reads input and strips packets with specified ether type. Ether type can be given as decimal value, or if prefixed with 0x, as a hexadecimal. Stripped packets are written into
  *epb_stripped_ethertype.&lt;ethertype&gt;.&lt;file_ext&gt;.*
  &lt;ethertype&gt; is replaced by given ethertype, and and &lt;file_ext&gt; depends on specified epb file format. Currently stripping pcap and snoop formats are supported. All other flags except -F, -f and -m are ignored when -E is set.
* **-C --strip-src-mac**  
  followed by mac. When epb is started with this flag, it reads input and strips packets with specified source mac. Mac address must be given as 
  *XX:XX:XX:XX:XX:XX*
  where each XX is a hexadecimal number without 0x prefix. Stripped packets are written into 
  file 
  *epb_stripped_src.&lt;mac&gt;.&lt;file_ext&gt;.*
  &lt;mac&gt; is replaced by specified mac, and &lt;file_ext&gt; depends on specified epb file format. Currently stripping pcap and snoop formats are supported. All other flags except -F, -f and -m are ignored when -C is set.
* **-T --strip-dst-mac**  
  followed by mac. When epb is started with this flag, it reads input and strips packets with specified destination mac. Mac address must be given as 
  *XX:XX:XX:XX:XX:XX*
  where each XX is a hexadecimal number without 0x prefix. Stripped packets are written into 
  file 
  *epb_stripped_dst.&lt;mac&gt;.&lt;file_ext&gt;.*
  &lt;mac&gt; is replaced by specified mac, and &lt;file_ext&gt; depends on specified epb file format. Currently stripping pcap formats are supported. All other
   flags except -F, -f and -m are ignored when -T is set.
* **-f --file**  
  followed by file where packet is specified. This or
  **-S is required**
* **-S --stdin**  
  packet file should be read from stdin. This or
  **-f is required**
* **-n --outif**  
  followed by interface name to determine out interface. This or 
  **-t is required**
* **-t --targetip**  
  followed by target IP (used only to determine out interface). This or 
  **-n is required**
* **-F --fileversion**  
  package file format - supported 1,2,pcap,pcapng,snoop (epb formats 1 and 2, libpcap/pcapng (tcpdump,wireshark..), snoop (SUN's sniffer) and netmon (MS Netmon's file format, versions 1 and 2)
* **-s --pkgsize**  
  followed by package size if 1500 is not big enough. NOTE: There is versions of epb which do not accept epb format files if size is not specified.
* **-j --interval-sec**  
  followed by interval (sec) - delay between packages defaults to 1 sec. See also 
  **-i** and **-u**
* **-i --interval-millisec**  
  followed by interval (msec) - delay between packages defaults to 1000 msec.
* **-u --interval-microsec**  
  followed by interval (micro sec) - delay between packages defaults to 1000000 micro sec
* **-d --delay**  
  followed by delay before sending first package, defaults to 0 sec.
* **-a --pkgamount**  
  followed by amount of packages to send (defaults to 1)
* **-w --block**  
  Wait for packets being sent (Do not fork)
* **-m --realmac**  
  Mac from hardware. Use real mac address as source mac. Specifying **-m** will cause interfaces real mac address being INSERTED at 6 bytes from the start of the package. **NOTE** when pcap file format is used, current epb implementation does not insert mac but OVERWRITES it instead. I am unsure if this is the best way, so behaviour may be changed in the future
* **-e --keependianess**  
  Endianess as given, do not do byte order conversions but send data as specified in file. This is only meaningfull with epb file formats. When binary file is used (like trace produced with pcap, snoop or netmon) the endianess conversion is never done.
* **-c --keepchecksum**  
  Checksum as given, do not calculate checksum even if protocol is recognized and checksum is zero. Checksum calculation is only done when epb file format is used (-F1 or -F2).**NOTE**: If offloading is enabled, HW may do some checksumming anyways.
* **-v --version**  
  display version and exit
* **-h --help**  
  display help and exit
* **-? --help**  
  display help and exit
  

# Epb Packet File Formats:

Currently two different plain text package file formats (for easy package crafting) and four captured data formats are recognized by epb. The old plain text format version 1 ( which is kept as default) is providing simple way to specify and send one kind of package(s). Since epb version 1.3 (Cold Fusion Bomb) there has also been file format version 2. Version 2 adds a header fields for packet specification file and provides mechanism to send sequences of different packages.
Both plain text file formats were developed aiming to simplicity both in parser and data specifying. File is interpreted line by line, and each line can either be a comment (ignored by parser), version 2 packet header field, or specify a piece of network packet data. Comment lines must be prefixed with 
**#**
character. Detailed specifications for epb plain text formats is below.

Version 1.4 (Two Handed Scissors) added support for sending captured pcap traces. It also included way to strip only packets with certain mac addresses for sending. 1.5 supports also reading snoop and netmon version 1 and 2 captures, and stripping snoop format.

**Version 1 format:**

: Version 1 file contains only comments and package data. Data pieces are specified by giving *length*:*value* pairs. One pair/line. Length can be one of following:
   

* u8  
  8 bit wide unsigned data
* i8  
  8 bit wide signed data
* u16  
  16 bit wide unsigned data
* i16  
  16 bit wide signed data
* u32  
  32 bit wide unsigned data
* i32  
  32 bit wide signed data
* u64  
  64 bit wide unsigned data
* i64  
  64 bit wide signed data

: *value* is simply specified as number. By default number is interpreted as decimal (base 10) number, but it can also be given as hexadecimal when prefixed with 0x


**Version 2 format:**

: 
  Packet data is specified as with version 1, but version 2 adds header fields and a tailer to separate different packets and to specify some sending characteristics for individual packets. Version 2 file must also be started with file version specification *--epb-file-version=2--* There is mandatory header fields and optional fields. Mandatory fields MUST be given for all packets and are meant to separate different packets. Optional fields can be used to override default sending characteristics (or command line options) per packet basis. Each header field must be started with *!* character.
  
  **Mandatory fields:**

* !packet_start  
  must be the first field stating start of the new packet.
* !header_end  
  this must be the last field in epb file header (just before actual packet data)
* !packet_end  
  this is the tailer and must be at the end of a packet, before
  *!packet_start*
  header stating start of new packet.

: **Optional fields:**

* !uenddelay  
  example: !uenddelay 1000, specifies microsecond delay before sending next packet. Defaults to 1000000. Affects all packets sent using !repeat.
* !enddelay  
  example: !enddelay 3, specifies second scale delay before sending next packet. Defaults to 1. Affects all packets sent using !repeat.
* !ustartdelay  
  example: !ustartdelay 1000, specifies microsecond delay before sending this packet. Defaults to 0. Does not delay repeated packets.
* !startdelay  
  example: !startdelay 3, specifies second scale delay before sending this packet. Defaults to 0. Does not delay repeated packets.
* !repeat  
  example: !repeat 3, can be used to send &lt;amount&gt; similar packets. NOTE: enddelay impacts to repeated packets. startdelay affects only to first packet.
  
  **Version 3 (pcap) format:**
  
    : 
      epb version 1.4 (and propably also possible later versions) support sending packets from pcap file (libpcap format). Pcap is de-facto packet specification file format in free world. Most of the popular free tools like *tcpdump*(8), *wireshark*(1) etc work with pcap. By default epb sends all packets as specified in pcap file. This is often not desirable way because usually capture files do contain both ingress and egress traffic data, and in most cases only the other direction is wished to be repeated. Epb supports stripping packets with certain source or destination mac address in a new pcap file which can then be sent. See *--pcap-strip-src-mac* or *--pcap-strip-dst-mac*.

  
  **Version 4 (snoop) format:**
  
    : 
      "epb version 1.5 (and propably also later versions) support sending packets from snoop file (SUN's sniffer format)."

  
  **Version 5 (netmon) format:**
  
    : "epb version 1.5 (and propably also later versions) support sending packets from netmon (.cap) file (Microsoft's netmon sniffer format). However only versions 1 and 2 of netmon traces are supported. If someone digs out the details of netmon version 3 captures I can think of adding support for that too."

  
  **Version 6 (pcapNG) format:**
  
    : 
      epb version 1.6 (and propably also later versions) support sending packets from pcapNG file (pcapNG format). PcapNG is slowly replacing pcap format. Many popular free tools like *wireshark*(1) etc work nowadays with pcapNG. The epb version 1.6 supports only really basics of pcapNG format, and may not work as expected with all pcapNG traces. Epb also fails with traces containing packets from more than one interface. I have however successfully sent simple pcapNG trace stored using wireshark. Currently packet stripping is not supported with pcapNG format, but it is possible to convert pcapNG file to epb2 format with -H option.

  
  

# Files

*examplepackets/icmp_v6_echo.packet*
: Example file showing icmpv6 echo packet

*examplepackets/icmp_v6_echo_filev2.packet*
: Example file showing sending bunch of icmpv6 echo packets


# Bugs


* **Current versions**  
  Using QinQ (802.1ad) double VLAN tagging will make IPv4 protocol detection not working =&gt; automatic checksum calculation not working. 
* **Versions before 1.1 (Bladeless Dagger)**  
  Using endianess maintaining introduced in 1.0 (Overweight Ninja) release make IPv4 protocol detection not working.
  This happens also when 802.1q tagged package is sent. (fixed in v1.1)

If you find (m)any other, fix them please =)

# Author

Matti Vaittinen &lt;[Mazziesaccount@gmail.com](mailto:Mazziesaccount@gmail.com)&gt; For license information see LICENSE file in package root.


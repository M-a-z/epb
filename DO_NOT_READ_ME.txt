I KNEW YOU CAN'T RESIST IT :D

This is a simple ethernet package sender.
You can send packets from 
 - epb's custom text file (format described below and in details at man pages. There's also example packet files included)
 - pcap traces
 - snoop traces
 - netmon v1 and v2 traces
 - pcapNG traces (first limited support added in epb v1.6)

You can test it with following steps:

1. build epb by typing "make myday"
2. launch wireshark
3. issue command


sudo epb -n eth0 -f examplepackets/icmp_v6_echo.packet -a 5
You should see 5 ICMP echo packages in wireshark log being sent to eth0.

examples:

sudo epb -n eth0 -f sniffed.snoop -F snoop
sudo epb --outif eth0 -f sniffed.snoop -F snoop

    =>  Send packets from interface eth0
        Packets are read from file 'sniffed.snoop'
        which format is snoop

sudo epb -t 192.168.0.1 -f sniffed.pcapng -F pcapng 
sudo epb --targetip 192.168.0.1 --file sniffed.pcapng --fileversion pcapng

    =>  Send packets from interface which would be used when trying to reach IP 192.168.0.1.
        Packets are read from file 'sniffed.pcapng' 
        which format is pcapng

sudo epb -H -f capturedpcapngfile.pcapng -F pcapng
sudo epb --humanreadable --fileversion pcapng --file capturedpcapngfile.pcapng

    =>  convert to text file (epb2 format).
        Original file is pcapng type file 
        called capturedpcapngfile.
        (Output file is named epb_converted.packet)




Note, as of epb version 1.3 there has been support for epb packet file format 2 allowing specifying sequence of packets. See man pages and examplepackets directory for more information about new file format.

So basically you specify package you wish to send in a text file, using format
<datalen>:<value>
<datalen>:<value>
<datalen>:<value>
<datalen>:<value>
...

For example
u8:0xaa
u8:0xbb
...

Lines starting with # are interpreted as comments. See examplepackets folder for examples.


NOTE: When you generate IPv4 packages, you can leave IP checksum to be 0. Then the sender calculates and fills it. Other checksums must be calculated by user, and given from pkgfile correctly. (Hint: you can first send packages with invalid checksum, and capture them by wireshark. Wireshark can then show you what the checksums should've been and you can fix them).

Commands:

sudo make maninstall
man epb

or
make man
sudo make install
ebp -h

can tell you more

Enjoy

-MVa


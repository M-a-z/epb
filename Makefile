CC=gcc
CFLAGS = -Wall -ggdb -m32
#LDFLAGS = -static
LDFLAGS =
DEFINES = -D_GNU_SOURCE

LIBS = -lpthread
MYDAYSRC=EthPkgBombardier.c epb_filev2_parser.c epb_filev1_parser.c epb_packetReader.c epb_pcap_parser.c epb_helpers.c epb_snoop_parser.c epb_netmon_parser.c epb_pcap_ng_parser.c
MYDAYTGT=bin/epb

all: myday man
myday:
	$(CC) $(CFLAGS) $(MYDAYSRC) -o $(MYDAYTGT) $(LDFLAGS) $(LIBS) $(DEFINES)
man: epb.8.gz
clean:
	rm -rf *core*
	rm -rf $(MYDAYTGT)
	rm -rf *.o
	rm -rf epb.8.gz

install: $(MYDAYTGT) maninstall
	cp $(MYDAYTGT) /usr/bin/.

maninstall: epb.8.gz
	mv epb.8.gz /usr/share/man/man8/.
	@echo 'man pages installed to /usr/share/man/man8'
	@echo 'consider running mandb or makewhatis to update apropos database'

help:
	@echo 'Possible make targets are:'
	@echo 'make all - prepare man pages and PC binaries'
	@echo 'make myday - prepare binaries'
	@echo 'make man - prepare man pages'
	@echo 'make install - install binary and man pages.'


epb.8.gz: man/epb.8
	cp man/epb.8 epb.8
	gzip epb.8

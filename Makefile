# FIXME: use libs only where required
CFLAGS=-ansi -Wall -ggdb
# libxml
CFLAGS+=${shell xml2-config --cflags}
LDFLAGS+=${shell xml2-config --libs}
# cdk
CFLAGS+=-I/usr/include/cdk
LDFLAGS+=-lcdk -lncurses
# openssl
LDFLAGS+=-lssl
# readline and history
LDFLAGS+=-lreadline -lhistory

all: readtoken readtoken_cli cryptodevcfg cryptokencfg masterkeycfg cryptousercfg
readtoken: readtoken.o shm.o pkcs5_pbkdf2.o util.o tokencommon.o globalvars.o
readtoken_cli: readtoken_cli.o shm.o pkcs5_pbkdf2.o util.o tokencommon.o globalvars.o
cryptodevcfg: cryptodevcfg.o shm.o util.o shell.o devcfgcommands.o globalvars.o ctabcommon.o
cryptokencfg: cryptokencfg.o util.o shell.o tokencfgcommands.o pkcs5_pbkdf2.o tokencommon.o globalvars.o
cryptousercfg: cryptousercfg.o util.o shell.o usercfgcommands.o pkcs5_pbkdf2.o tokencommon.o globalvars.o shm.o ctabcommon.o
masterkeycfg: masterkeycfg.o shm.o util.o globalvars.o
diskimage:
	dd if=/dev/zero of=diskimage bs=1M count=10 && losetup /dev/loop0 diskimage && mkfs.ext2 /dev/loop0 && losetup -d /dev/loop0
clean:
	rm -f *.o readtoken cryptodevcfg masterkeycfg cryptokencfg readtoken_cli cryptousercfg

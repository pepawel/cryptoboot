#ifndef _ALL_H_
#define _ALL_H_

#define _SVID_SOURCE /* ipc.h */
#define CONFIG_FILE "/etc/cryptoboot/cryptotab.xml"
#define LOOP_SET_FD 0x4c00 /* loop ioctl */
#define LOOP_CLR_FD 0x4c01 /* loop ioctl */
#define LOOP_SET_STATUS64 0x4c04 /* loop ioctl */
#define LOOP_GET_STATUS				0x4C03 /* loop ioctl */
#define LOOP_MULTI_KEY_SETUP 0x4c4d /* loop ioctl */
#define CIPHER_AES 16 /* loop_info64 */
#define LO_NAME_SIZE 64 /* max size of device name in loopaes module */
#define LO_KEY_SIZE 32 /* max size of the key in loopaes */

#define MAGIC_STRING "cryptobootmagic" /* 15 characters + null */

#include <stdio.h>
#include <string.h>
#include <sys/ipc.h> /* shmget, ftok */
#include <sys/shm.h> /* shmget, shmat */
#include <sys/types.h> /* ftok, shmat, open */
#include <stdlib.h> /* malloc */
#include <unistd.h> /* exit, close */
#include <sys/stat.h> /* open */
#include <fcntl.h> /* open */
#include <sys/mount.h> /* mount */
/* xml */
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>
#include <libxml/xmlschemas.h>
#include "cdk.h" /* all cdk functions */
/* openssl crypto */
#include <openssl/aes.h>
#include <openssl/rand.h> /* RAND_bytes */
#include <openssl/err.h> /* ERR_get_error */

#include "types.h"
#include "shm.h"
#include "pkcs5_pbkdf2.h"
#include "util.h"

int usleep(); /* not declaring this results in compiler warnings */

/* FIXME: move to other header file */
struct loop_info64 {
	u_int64_t	lo_device; 		/* ioctl r/o */
	u_int64_t	lo_inode; 		/* ioctl r/o */
	u_int64_t	lo_rdevice; 		/* ioctl r/o */
	u_int64_t	lo_offset;		/* bytes */
	u_int64_t	lo_sizelimit;		/* bytes, 0 == max available */
	u_int32_t	lo_number;		/* ioctl r/o */
	u_int32_t	lo_encrypt_type;
	u_int32_t	lo_encrypt_key_size; 	/* ioctl w/o */
	u_int32_t	lo_flags;		/* ioctl r/o */
	unsigned char	lo_file_name[LO_NAME_SIZE];
	unsigned char	lo_crypt_name[LO_NAME_SIZE];
	unsigned char	lo_encrypt_key[LO_KEY_SIZE]; /* ioctl w/o */
	u_int64_t	lo_init[2];
};


#endif

#include "all.h"

#define SECTOR_SIZE 512
#define READ_TRIES 3
#define WRITE_TRIES 3

#include <stdio.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <stdlib.h>
#include "shell.h"
#include "cryptodevcfg.h"
#include <sys/types.h> /* opendir, readdir */
#include <dirent.h> /* opendir, readdir */
#include <fcntl.h>
#include "globalvars.h"

/* FIXME: TODO: 'setup' command for attaching loop to device?
 *              if implementing setup, then another
 *              field in 'list' - attached - would be needed */

	
void
printDeviceLine(index, node)
	int index;
	xmlNodePtr node;
{
	xmlChar* dst;
	xmlChar* src;
	xmlChar* driver;
	xmlChar* action;
	dst = xmlGetProp(node, "dst");
	src = xmlGetProp(node, "src");
	action = xmlGetProp(node, "action");
	driver = (xmlChar*) node->name;
	
	printf(" %2d\r", index);
	printf(" \t%s\r", dst);
	printf(" \t\t\t\t%s\r", src);
	printf(" \t\t\t\t\t\t%s\r", driver);
	if (NULL != action)
		printf(" \t\t\t\t\t\t\t\t%s\n", action);
	else	
		printf("\n");
	
	xmlFree(dst);
	xmlFree(src);
	xmlFree(action);
	return;
}

int
cList(arg)
	char* arg;
{
	xmlNodePtr* dtab;
	int i;
	fillDeviceTab(&dtab);
	if (NULL == dtab[0])
		printf("No devices defined in configuration file.\n");
	else
	{
		printf("  #\r");
		printf(" \tTarget device\r");
		printf(" \t\t\t\tSource device\r");
		printf(" \t\t\t\t\t\tDriver\r");
		printf(" \t\t\t\t\t\t\t\tAction\n");
		for (i = 0; NULL != dtab[i]; i++)
		{
			printDeviceLine(i, dtab[i]);
		}
	}
	free(dtab);

	return 1;
}

int
findFreeLoop(out_loop)
	char** out_loop;
{
	char* loop;
	DIR* dir;
	struct dirent* ent;
	char* dev;
	int fd, ret;
	struct loop_info64 li;
	char* fullname;
	
	dir = opendir("/dev/");
	if (NULL == dir)
		return -1;
	
	/* Scan dev directory */
	loop = (char*) NULL;
	while( NULL != (ent = readdir(dir)))
	{
		dev = ent->d_name;
		/* For every loop device found check if it is unused */
		if (0 == strncmp(dev, "loop", 4))
		{
			xstrcat(&fullname, "/dev/", dev);
			fd = open(fullname, O_RDWR);
			if (-1 != fd)
			{
				ret = ioctl(fd, LOOP_GET_STATUS, &li);
				if (-1 == ret)
				{
					/* Found unused loop device */
					loop = strdup(fullname);
				}
				close(fd);
			}
			free(fullname);
			if (NULL != loop)
				break;
		}
	}
	closedir(dir);
	
	if (NULL == loop)
		return -1;
	
	*out_loop = loop;
	return 1;
}

int
getBlocksNum(out_numblocks, dev)
	unsigned long* out_numblocks;
	char* dev;
{
	int fd, ret;
	unsigned long numblocks;
	fd = open(dev, O_RDONLY);
	if (-1 == fd)
		return -1;
	ret = ioctl(fd, BLKGETSIZE, &numblocks);
	close(fd);

	if (-1 != ret)
		*out_numblocks = numblocks;

	return ret;
}

int
readBlock(src, buf, i, out_error)
	int src;
	char* buf;
	unsigned long i;
	char** out_error;
{
	int result;
	int readTriesLeft;
	off_t oret;
	int br;

	readTriesLeft = READ_TRIES;
	result = 0;
	while (readTriesLeft > 0)
	{
		/* Position file pointer in correct place */
		oret = lseek(src, i * ((off_t) SECTOR_SIZE), SEEK_SET);
		if (-1 == oret)
		{
			/* Seek failed - fatal error - abort */
			*out_error = strerror(errno);
			result = -1;
			break;
		}
		
		/* Read data from src to buffer */
		br = read(src, buf, SECTOR_SIZE);
		readTriesLeft--;
		if (SECTOR_SIZE == br)
		{
			/* Read full sector - ok */
			*out_error = "Ok";
			result = 1;
			break;
		}
		else if (-1 == br)
		{
			/* Check errno */
			if (EIO == errno)
			{
				/* I/O error - probably bad block - continue */
				*out_error = strerror(errno);
				result = 0;
				break;
			}
			else if (EINTR == errno)
			{
				/* Read interrupted by signal - no data read.
				 * Need to repeat read of this block */
				*out_error = strerror(errno);
				result = 0;
				continue;
			}
			else
			{
				/* Unknown error - abort */
				*out_error = strerror(errno);
				result = -1;
				break;
			}
		}
		else if (br == 0)
		{
			/* End of file */
			*out_error = "Premature end of file";
			result = -1;
			break;
		}
		else
		{
			/* Read too few data - repeat read */
			*out_error = "Too small data block read";
			result = 0;
			continue;
		}
	}

	return result;
}

int
writeBlock(dst, buf, i, out_error)
	int dst;
	char* buf;
	unsigned long i;
	char** out_error;
{
	int result;
	int writeTriesLeft;
	off_t oret;
	int bw;

	writeTriesLeft = WRITE_TRIES;
	result = 0;
	while (writeTriesLeft > 0)
	{
		/* Position file pointer in correct place */
		oret = lseek(dst, i * ((off_t) SECTOR_SIZE), SEEK_SET);
		if (-1 == oret)
		{
			/* Seek failed - fatal error - abort */
			*out_error = strerror(errno);
			result = -1;
			break;
		}
		
		/* Write data from buffer to dst */
		bw = write(dst, buf, SECTOR_SIZE);
		writeTriesLeft--;
		if (SECTOR_SIZE == bw)
		{
			/* Full sector written - ok */
			*out_error = "Ok";
			result = 1;
			break;
		}
		else if (-1 == bw)
		{
			/* Check errno */
			if (EIO == errno)
			{
				/* I/O error - probably bad block - continue */
				*out_error = strerror(errno);
				result = 0;
				break;
			}
			else if (EINTR == errno)
			{
				/* Write interrupted by signal - no data was written.
				 * Need to repeat write of this block */
				*out_error = strerror(errno);
				result = 0;
				continue;
			}
			else
			{
				/* Unknown error - abort */
				*out_error = strerror(errno);
				result = -1;
				break;
			}
		}
		else if (bw == 0)
		{
			/* Empty write */
			*out_error = "Nothing was written";
			result = -1;
			break;
		}
		else
		{
			/* Written too few data - repeat write */
			*out_error = "Too small data block written";
			result = 0;
			continue;
		}
	}

	return result;
}

/* FIXME: add "CTRL-C stops encryption/decryption" feature */
int
ddProgress(srcName, dstName, numblocks)
	char* srcName;
	char* dstName;
	unsigned long numblocks;
{
	int src, dst;
	u_int8_t buf[SECTOR_SIZE];
	unsigned long i;
	int result, ret, updateProgress;
	char* errorString;
	unsigned long step;
	
	step = numblocks/100;
	if (step > 1024)
		step = 1024;
	
	result = -1;
	src = open(srcName, O_RDONLY);
	if (-1 != src)
	{
		dst = open(dstName, O_WRONLY);
		if (-1 == dst)
			close(src);
		else
		{
			updateProgress = 1;
			for (i = 0;; i++)
			{
				if ((0 == (i % step))
						|| (i == (numblocks - 1))
						|| (1 == updateProgress))
					fprintf(stderr, "\r%lu/%lu [%lu%%]", i + 1, numblocks,
									(i * 100) / (numblocks - 1));
	
				updateProgress = 0;
				
				if (i >= numblocks)
				{
					fprintf(stderr, "\n");
					result = 1;
					break;
				}
				
				ret = readBlock(src, buf, i, &errorString);
				if (-1 == ret)
				{
					/* Fatal read error - abort */
					fprintf(stderr,
									"\nFatal error reading sector %lu: %s\n",
									i + 1, errorString);
					break;
				}
				else if (0 == ret)
				{
					/* Non fatal read error - do not write this block */
					fprintf(stderr,
									"\nError reading sector %lu: %s\n",
									i + 1, errorString);
					updateProgress = 1;
					continue;
				}
			
				ret = writeBlock(dst, buf, i, &errorString);
				if (-1 == ret)
				{
					/* Fatal write error - abort */
					fprintf(stderr,
									"\nFatal error writing sector %lu: %s\n",
									i + 1, errorString);
					break;
				}
				else if (0 == ret)
				{
					/* Non fatal write error */
					fprintf(stderr,
									"\nError writing sector %lu: %s\n",
									i + 1, errorString);
					updateProgress = 1;
					continue;
				}
			}
			close(dst);
		}
		close(src);
	}
	return result;
}

void
performCryptoAction(device)
	xmlNodePtr device;
{
	int ret;
	char* loop;
	xmlChar* driver;
	xmlChar* src;
	char* out_error;
	u_int8_t* mk;
	xmlChar* emkt;
	xmlChar* action;
	unsigned long numblocks;
	
	driver = (xmlChar*) device->name;
	/* Get src device */
	src = xmlGetProp(device, "src");
	printf("%s: ", src);
	if (0 == xmlStrcmp(driver, "loopaes"))
	{
		ret = findFreeLoop(&loop);
		if (-1 == ret)
			printf("No free /dev/loop devices found.\n");
		else
		{
			/* Get key */
			emkt = xmlNodeListGetString(ctab, device->xmlChildrenNode, 1);
			ret = loopaesGetMultiKey(&mk, device);
			xmlFree(emkt);
			if (-1 == ret)
			{
				printf("Error: Could not get multikey.\n");
			}
			else
			{
				/* Setup device using temporary loop */
				ret = loopaesSetupDevice(mk, src, loop, &out_error);
				if (-1 == ret)
				{
					printf("Error setting device: %s.\n", out_error);
				}
				else
				{
					/* Perform crypto operation depending on action */
					action = xmlGetProp(device, "action");
					if (NULL == action)
					{
						printf("No action requested for this device.");
					}
					else
					{
						if (0 == xmlStrcmp(action, "encrypt"))
						{
							printf("Performing encryption using '%s' as temporary loop device...\n", loop);
							ret = getBlocksNum(&numblocks, loop);
							if (-1 == ret)
							{
								printf("Could not get device size.\n");
							}
							else
							{
								ret = ddProgress(src, loop, numblocks);
								if (-1 == ret)
								{
									printf("Encryption failure.\n");
								}
								else
								{
									xmlUnsetProp(device, "action");
									printf("Encryption complete. Removed 'encrypt' mark from device.\n");
								}
							}
						}
						else if (0 == xmlStrcmp(action, "decrypt"))
						{

							printf("Performing decryption using '%s' as temporary loop device...\n", loop);
							ret = getBlocksNum(&numblocks, loop);
							if (-1 == ret)
							{
								printf("Could not get device size.\n");
							}
							else
							{
								ret = ddProgress(loop, src, numblocks);
								if (-1 == ret)
								{
									printf("Decryption failure.\n");
								}
								else
								{
									xmlUnlinkNode(device);
									xmlFreeNode(device);
									printf("Decryption complete. Device removed from configuration.\n");
								}
							}
						}
						else
							printf("Unknown action '%s'.", action);
					}
					xmlFree(action);
					ret = loopaesDetachDevice(loop);
					if (-1 == ret)
						printf("Error: Could not detach loop device '%s'.\n", loop);
				}
			}
			free(loop);
		}
	}
	else
		printf("FIXME: Encryption/decryption in '%s' driver not implemented.\n", driver);
	xmlFree(src);
	return;
}

int cStartCrypto(arg)
	char* arg;
{
	xmlNodePtr* dtab;
	int i, wasAction, step, answer;
	xmlChar* action;
	xmlChar* src;
	xmlChar* driver;
	
	fillDeviceTab(&dtab);
	wasAction = 0;
	step = 0;
	for (i = 0; NULL != dtab[i]; i++)
	{
		action = xmlGetProp(dtab[i], "action");
		if (NULL != action)
		{
			step++;
			if (0 == wasAction)
			{
				wasAction = 1;
				printf("Following steps will be taken:\n");
			}
			src = xmlGetProp(dtab[i], "src");
			driver = (xmlChar*) dtab[i]->name;
			printf("%d. %s %s with %s\n", step, action, src, driver);
			xmlFree(src);
			xmlFree(action);	
		}
	}
	if (0 == step)
	{
		printf("No crypto actions defined.\n");
	}
	else
	{
		answer = ynQuestion("\nAre you sure?", 'n');
		if ('y' == answer)
		{
			for (i = 0; NULL != dtab[i]; i++)
			{
				action = xmlGetProp(dtab[i], "action");
				if (NULL != action)
					performCryptoAction(dtab[i]);
				xmlFree(action);	
			}
			printf("You should save changes to config file by issuing 'save' command.\n");
		}
	}

	free(dtab);

	return 1;
}

int
cHelp(arg)
	char* arg;
{
	int i;
	printf("Possible commands:\n");
	for(i = 0; NULL != commands[i].name; i++)
		printf("\t%s %s\r\t\t\t%s\n", commands[i].name, commands[i].args,
																		commands[i].doc);
	return 1;
}

int
cShowkey(arg)
	char* arg;
{
	unsigned long di;
	int ret;
	xmlChar* src;
	xmlNodePtr* dtab;
	xmlNodePtr device;
	
	xmlChar* driverName;
	u_int8_t* laDMultiKey; 
	int i, j;
	
	if (NULL == arg)
	{
		printf("Device number as argument required.\n");
		return 1;
	}
	ret = str2num(&di, arg);
	if (-1 == ret)
	{
		printf("Bad index '%s'.\n", arg);
		return 1;
	}
	
	fillDeviceTab(&dtab);
	
	ret = getNode(&device, dtab, di);
	if (-1 == ret)
	{
		printf("No such device.\n");
	}
	else
	{
		/* Get encrypted key */
		driverName = (xmlChar*) device->name;

		if (0 == xmlStrcmp(driverName, "loopaes"))
		{
			ret = loopaesGetMultiKey(&laDMultiKey, device);
					
			if (ret == -1)
			{
				fprintf(stderr, "Internal error.\n");
				exit(1);
			}
					
			/* Print decrypted key */
			src = xmlGetProp(device, "src");
			printf("Key material for device '%s' (loopaes multikey):\n\n",
						 src);
			xmlFree(src);
			for (i = 0; i < 64; i++)
			{
				printf("\t");
				for (j = 0; j < 128/8; j++)
				{
					printf("%.2x", laDMultiKey[j + (i*128/8)]);
				}
				printf("\n");
			}
			free(laDMultiKey);
		}
		else if (0 == xmlStrcmp(driverName, "plainloop"))
		{
			src = xmlGetProp(device, "src");
			printf("Device '%s' uses %s driver, which does not need a key.\n", src, driverName);
			xmlFree(src);
		}
		else
		{
			printf("FIXME: %s driver key printing not implemented.\n",
						 driverName);
		}
	}
	free(dtab);
	return 1;
}

int
cDecrypt(arg)
	char* arg;
{
	unsigned long di;
	int ret;
	xmlChar* src;
	xmlNodePtr* dtab;
	xmlNodePtr device;
	xmlChar* oldAction;
	char answer;
	
	if (NULL == arg)
	{
		printf("Device number as argument required.\n");
		return 1;
	}
	ret = str2num(&di, arg);
	if (-1 == ret)
	{
		printf("Bad index '%s'.\n", arg);
		return 1;
	}
	
	fillDeviceTab(&dtab);
	
	ret = getNode(&device, dtab, di);
	if (-1 == ret)
	{
		printf("No such device.\n");
	}
	else
	{
		src = xmlGetProp(device, "src");
		oldAction = xmlGetProp(device, "action");
		if (NULL == oldAction)
		{
			xmlSetProp(device, "action", "decrypt");
	
			printf("Device '%s' marked for decryption.\n", src);
			printf("To start decryption process type 'startcrypto'.\n");
		
		}
		else if (0 == xmlStrcmp(oldAction, "encrypt"))
		{
			printf("According to configuration device '%s' is not encrypted (only marked for encryption). Insted of decryption, its entry will be removed.\n", src);
			printf("It means the key material associated with this device will be removed also.\n");
			answer = ynQuestion("Are you sure?", 'n');
			if ('y' == answer)
			{
				xmlUnlinkNode(device);
				xmlFreeNode(device);
				printf("Device '%s' removed from configuration.\n", src);
			}
		}
		else
		{
			printf("Device '%s' is already marked for decryption.\n", src);
		}
		xmlFree(src);
		xmlFree(oldAction);
	}
	free(dtab);
	return 1;
}

int
addLoopaesDevice(src, dst, dkey, action)
	char* src;
	char* dst;
	u_int8_t* dkey;
	char* action;
{
	AES_KEY ik;
	int i;
	u_int8_t* ekey;
	char* ekeyText;
	xmlNodePtr cur, devicesNode, device;
	
	/* Encrypt multikey using masterKey */
	AES_set_encrypt_key(authdata, 128, &ik);

	ekey = malloc(64*128/8);
	if (NULL == ekey)
		return -1;
	
	/* Encryption in ECB mode - safe for random data such as keys */
	for (i = 0; i < 64; i++)
		AES_ecb_encrypt(dkey + (i*128/8), ekey + (i*128/8),
										&ik, AES_ENCRYPT);

	/* Convert encrypted key to xmlChar* */
	byte2hex(&ekeyText, ekey, 64*128/8);
	
	/* Find devices node */
	cur = xmlDocGetRootElement(ctab);
	for (cur = cur->xmlChildrenNode; cur != NULL; cur = cur->next)
	{
		if (0 == xmlStrcmp(cur->name, "devices"))
		{
			devicesNode = cur;
			break;
		}
	}
	/* Create device node */
	device = xmlNewTextChild(devicesNode, NULL, "loopaes", NULL);
	/* Create and fill properties of device node */
	xmlSetProp(device, "src", src);
	xmlSetProp(device, "dst", dst);
	xmlSetProp(device, "action", action);
	/* Create and fill multikey node */
	xmlNewTextChild(device, NULL, "multikey128", ekeyText);
	free(ekeyText);
	return 1;
}

void
encryptionWizard()
{
	char* src;
	char* dst;
	char* rawSrc;
	char* rawDst;
	char answer;
	u_int8_t* key;
	int ret;
	
	printf("Please specify new device parameters.\n");
	printf("Driver: loopaes\n"); /* FIXME: FUTURE: give choice */
	rawSrc = readline("Source device: ");
	rawDst = readline("Target device: ");
	answer = ynQuestion("Do you want to manually enter the key?", 'n');
	if ('y' == answer)
	{
		printf("FIXME: Sorry, this function is not yet implemented.\n");
	}
	/* else FIXME */
	{
		printf("Generating key... ");
		key = malloc(64*128/8);
		if (NULL == key)
		{
			printf("Memory allocation error.\n");
			exit(1);
		}
		ret = RAND_bytes(key, 64*128/8);
		if (0 == ret)
		{
			printf("RAND_bytes: %lu\n", ERR_get_error());
			exit(1);
		}
		printf("done.\n");
	}
	src = trim(rawSrc);
	dst = trim(rawDst);
	addLoopaesDevice(src, dst, key, "encrypt");
	free(key);
	
	printf("Device '%s' added to cryptotab.\n", src);
	printf("You should save changes issuing 'save', then start encryption process\nby issuing 'startcrypto'.\n");
	
	free(rawSrc);
	free(rawDst);
	
	return;
}

int
cEncrypt(arg)
	char* arg;
{
	unsigned long di;
	int ret;
	xmlChar* src;
	xmlNodePtr* dtab;
	xmlNodePtr device;
	xmlChar* oldAction;

	char answer;
	
	fillDeviceTab(&dtab);
	
	if (NULL != arg)
	{
		ret = str2num(&di, arg);
		if (-1 == ret)
		{
			printf("Bad index '%s'.\n", arg);
			return 1;
		}
		
		ret = getNode(&device, dtab, di);
		if (-1 == ret)
		{
			printf("No such device.\n");
		}
		else
		{
			src = xmlGetProp(device, "src");
			oldAction = xmlGetProp(device, "action");
			if (NULL == oldAction)
			{
				printf("According to configuration file, device '%s' is already encrypted.\n", src);
				printf("Warning: Double encryption could destroy data on device.\n");
				answer = ynQuestion("Are you sure?", 'n');
				if ('y' == answer)
				{
					xmlSetProp(device, "action", "encrypt");
		
					printf("Device '%s' marked for encryption.\n", src);
					printf("To start encryption process type 'startcrypto'.\n");
				}
			}
			else if (0 == xmlStrcmp(oldAction, "decrypt"))
			{
				xmlUnsetProp(device, "action");
				printf("'decrypt' mark removed from device '%s'.\n", src);
			}
			else
			{
				printf("Device '%s' is already marked for encryption.\n", src);
			}
			xmlFree(src);
			xmlFree(oldAction);
		}
	}
	else
	{
		encryptionWizard();
	}
	free(dtab);
	return 1;
}

int
cSave(arg)
	char* arg;
{
	int ret;
	char* file;
	char answer;
	if (NULL != arg)
		file = arg;
	else
		file = CONFIG_FILE;
	
	printf("Configuration will be written to '%s'.\n", file);
	answer = ynQuestion("Are you sure?", 'n');
	if (answer == 'y')
	{
		ret = xmlSaveFormatFile(file, ctab, 1);
		if (-1 == ret)
			printf("Writing configuration to file '%s' failed.\n", file);
		else
			printf("Configuration saved to '%s'\n", file);
	}
	return 1;
}

int
cQuit(arg)
	char* arg;
{
	return -1;
}

Command commands[] =
{
	{"list", cList, "List devices", ""},
	{"encrypt", cEncrypt, "Add new device and encrypt it, or mark n for encryption", "[n]"},
	{"decrypt", cDecrypt, "Mark device n for decryption", "n"},
	{"showkey", cShowkey, "Show encryption key for device n", "n"},
	{"startcrypto", cStartCrypto, "Start encryption/decryption of selected devices", ""},
	{"save", cSave, "Save changes to configuration file", "[file]"},
	{"help", cHelp, "Display help", ""},
	{"quit", cQuit, "Quit program", ""},
	{(char*) NULL, (rl_icpfunc_t*) NULL, (char*) NULL}
};


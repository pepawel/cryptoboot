#include "all.h"
#include <readline/readline.h>
#include <readline/history.h>
#include "shell.h"
#include "cryptodevcfg.h"
#include "globalvars.h"
#include "ctabcommon.h"

/* FIXME: TODO: Implement -da for loop detaching */
/* FIXME: in every function check if device is already set up */

int
fillDeviceTab(out_tab)
	xmlNodePtr** out_tab;
{
	xmlNodePtr dev, cur, root;
	xmlNodePtr* tab;
	int i;
	
	/* Count elements */
	root = xmlDocGetRootElement(ctab);
	i = 0;
	for (cur = root->xmlChildrenNode; cur != NULL; cur = cur->next)
	{
		if (0 == xmlStrcmp(cur->name, "devices"))
		{
			for (dev = cur->xmlChildrenNode; dev != NULL; dev = dev->next)
				if (0 != xmlStrcmp(dev->name, "text"))
					i++;
			break;
		}
	}

	tab = malloc(sizeof(xmlNodePtr) * (i + 1));
	
	i = 0;
	for (cur = root->xmlChildrenNode; cur != NULL; cur = cur->next)
	{
		if (0 == xmlStrcmp(cur->name, "devices"))
		{
			for (dev = cur->xmlChildrenNode; dev != NULL; dev = dev->next)
				if (0 != xmlStrcmp(dev->name, "text"))
				{
					tab[i]= dev;
					i++;
				}
			break;
		}
	}
	
	tab[i] = (xmlNodePtr) NULL;
	
	*out_tab = tab;
	
	return 1;
}

int
loopaesDetachDevice(loop)
	char* loop;
{
	int ret;
	int loopfd;
	loopfd = open(loop, O_RDWR);
	if (-1 == loopfd)
		return -1;

	ret = ioctl(loopfd, LOOP_CLR_FD, 0);
	close(loopfd);
	if (-1 == ret)
		return -1;
	else
		return 1;
}

/* FIXME: Implement owner and perm of shared memery segment chacking */
/* FIXME: detach loop device on any error! */
int
loopaesSetupDevice(mk, src, dst, out_error)
	u_int8_t* mk;
	char* src;
	char* dst;
	char** out_error;
{
	int rdev, ldev;
	int ret;
	u_int8_t internalMK[64][256/8];
	struct loop_info64 li;
	int i, j;

	/* Opening real device and loop device */
	rdev=open(src,O_RDWR);
	if (rdev == -1)
	{
		*out_error = "Src device opening failed";
		return -1;
	}
	ldev=open(dst,O_RDWR);
	if (ldev == -1)
	{
		*out_error = "Dst device opening failed";
		close(rdev);
		return -1;
	}
	
	/* If dst device is busy, return error */
	ret = ioctl(ldev, LOOP_GET_STATUS, &li);
	if (ret != -1)
	{
		*out_error = "Dst device busy";
		close(rdev);
		close(ldev);
		return -1;
	}
	
	/* Telling kernel module to setup loopback device */
	ret=ioctl(ldev, LOOP_SET_FD, rdev);
	if (ret == -1)
	{
		*out_error = "LOOP_SET_FD failed";
		close(rdev);
		close(ldev);
		return -3;
	}
	
	/* Filling loopinfo structure */
	memset(&li, 0, sizeof(li));
	strncpy(li.lo_file_name, src, LO_NAME_SIZE);
	li.lo_encrypt_type=CIPHER_AES;
	li.lo_encrypt_key_size=128/8;
	
	ret=ioctl(ldev, LOOP_SET_STATUS64, &li);
	if (ret == -1)
	{
		*out_error = "LOOP_SET_STATUS64 failed";
		close(rdev);
		close(ldev);
		return -4;
	}
	
	/* Prepare internal multi key */
	for (j = 0; j < 64; j++)
	{
		for (i = 0; i < 128/8; i++)
			internalMK[j][i] = mk[i+(j*128/8)];
	}

	ret=ioctl(ldev, LOOP_MULTI_KEY_SETUP, &internalMK[0][0]);
	if (ret == -1)
	{
		*out_error = "LOOP_MULTI_KEY_SETUP failed";
		close(rdev);
		close(ldev);
		ioctl(ldev, LOOP_CLR_FD, 0);
		return -5;
	}
	
	/* Cleaning up */
	close(rdev);
	close(ldev);
	
	return 1;
}

int
plainloopSetupDevice(src, dst, out_error)
	char* src;
	char* dst;
	char** out_error;
{
	int rdev, ldev;
	int ret;
	struct loop_info64 li;
	
	/* Opening real device and loop device */
	rdev = open(src, O_RDWR);
	if (rdev == -1)
	{
		*out_error = "Src device opening failed";
		return -1;
	}
	ldev = open(dst, O_RDWR);
	if (ldev == -1)
	{
		*out_error = "Dst device opening failed";
		close(rdev);
		return -1;
	}

	/* If dst device is busy, return error */
	ret = ioctl(ldev, LOOP_GET_STATUS, &li);
	if (ret != -1)
	{
		*out_error = "Dst device busy";
		close(rdev);
		close(ldev);
		return -1;
	}

	/* Telling kernel module to setup loopback device */
	ret = ioctl(ldev, LOOP_SET_FD, rdev);
	if (ret == -1)
	{
		*out_error = "LOOP_SET_FD failed";
		close(rdev);
		close(ldev);
		return -3;
	}

	/* Cleaning up */
	close(rdev);
	close(ldev);
	
	return 1;
}

int
loopaesGetMultiKey(out_dmk, device)
	u_int8_t** out_dmk;
	xmlNodePtr device;
{
	int ret, i;
	xmlChar* emkt;
	u_int8_t* emk;
	u_int8_t* dmk;
	AES_KEY ik;
	xmlNodePtr cur;
	
	/* Find multikey node */
	for (cur = device->xmlChildrenNode; cur != NULL; cur = cur->next)
	{
		if (0 == xmlStrcmp(cur->name, "multikey128"))
		{
			emkt = xmlNodeListGetString(ctab, cur->xmlChildrenNode, 1);
			cleanWhiteSpace((char**)(&emkt));
			ret = hex2byte(&emk, emkt, 64*128/8);
			xmlFree(emkt);
			if (ret == -1)
				return -1;
				
			/* Decrypt multikey using masterKey */
			AES_set_decrypt_key(authdata, 128, &ik);

			dmk = malloc(64*128/8);
			if (NULL == dmk)
				return -1;
	
			/* Decryption in ECB mode - safe for random data such as keys */
			for (i = 0; i < 64; i++)
				AES_ecb_encrypt(emk + (i*128/8), dmk + (i*128/8),
												&ik, AES_DECRYPT);

			*out_dmk = dmk;
			return 1;
		}
	}
	return -1;
}

void
driverDispatcher(node)
	xmlNodePtr node;
{
	xmlChar* driverName;
	xmlChar* laSrc;
	xmlChar* laDst;
	xmlChar* plSrc;
	xmlChar* plDst;
	char* errorString;
	int ret;
	u_int8_t* laDMultiKey;
	
	driverName = (xmlChar*) node->name;

	if (0 == xmlStrcmp(driverName, "loopaes"))
	{
		ret = loopaesGetMultiKey(&laDMultiKey, node);
				
		if (-1 == ret)
		{
			printf("Internal error.\n");
			exit(1);
		}
				
		laSrc = xmlGetProp(node, "src");
		laDst = xmlGetProp(node, "dst");
			
		printf("Setting device %s on %s using Loop-AES... ",
					 laSrc, laDst);
		ret = loopaesSetupDevice(laDMultiKey,laSrc,laDst,&errorString);
		free(laDMultiKey);
		xmlFree(laSrc);
		xmlFree(laDst);
		if (ret == -1)
			printf("error: %s.\n", errorString);
		else
			printf("ok.\n");
	}
	else if (0 == xmlStrcmp(driverName, "dmcrypt"))
	{
		printf("Setting device X on Y using dm-crypt... ");
		printf("FIXME: not implemented.\n");
	}
	else if (0 == xmlStrcmp(driverName, "plainloop"))
	{
		plSrc = xmlGetProp(node, "src");
		plDst = xmlGetProp(node, "dst");
		printf("Setting device %s on %s using plain loop... ",
					 plSrc, plDst);
		ret = plainloopSetupDevice(plSrc, plDst, &errorString);
		xmlFree(plSrc);
		xmlFree(plDst);
		if (ret == -1)
			printf("error: %s.\n", errorString);
		else
			printf("ok.\n");
	}
	else
	{
		printf("Unknown crypto-driver: %s\n", driverName);
		return;
	}

	return;
}

void setupAllDevices()
{	
	xmlNodePtr* dtab;
	xmlChar* action;
	int i;
	int wasSetupFlag;
	
	fillDeviceTab(&dtab);
	/* Setup all devices without associated actions */
	wasSetupFlag = 0;
	for (i = 0; NULL != dtab[i]; i++)
	{
		/* Check if this device has action */
		action = xmlGetProp(dtab[i], "action");
		if (NULL == action)
		{
			wasSetupFlag = 1;
			driverDispatcher(dtab[i]); /* no action - we can setup device */
		}
		else
			free(action);
	}
	if (0 == i)
		printf("No devices defined in configuration file.\n");
	else if (0 == wasSetupFlag)
		printf("No devices ready for setup.\n");
	
	free(dtab);
	
	return;
}

int
main(argc, argv)
	int argc;
	char** argv;
{
	int ret;
	/* xml */

	ret = getAuthdata(0);
	if (ret == -1)
	{
		perror("Shared memory error");
		exit(1);
	}

	ctab = xmlParseFile(CONFIG_FILE);
	if (ctab == NULL)
	{
		fprintf(stderr, "Config file parsing error.\n");
		shmdt(authdata);
		exit(1);
	}
	
	if ((argc > 1) && (0 == strcmp(argv[1], "-a")))
		setupAllDevices();
	else
	{
		printf("cryptodevcfg 0.1\n\n");
		ret = checkMKEncMagic();
		if (1 == ret)
		{
			printf("Type 'help' for help, 'quit' to exit program.\n");
			printf("You can use command completion with TAB key.\n");
		
			openShell();
		}
	}
		
	/* FIXME: on each exit do shmdt and free doc? */
	shmdt(authdata);

	xmlFreeDoc(ctab);
	
	return 0;
}

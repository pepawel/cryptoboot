#include "all.h"
#include "util.h"
#include "globalvars.h"
#include "tokencommon.h"


int
main(argc, argv)
	int argc;
	char** argv;
{
	int error = 0;
	char* ctokenFile;
	int ret, i;
	xmlNodePtr tUserNode, dUserNode;
	char* passphrase;
	u_int8_t* utk;
	u_int8_t* mk;
	xmlChar* tokenDev;
	xmlChar* tokenFS;
	xmlChar* tokenDir;
	xmlChar* tokenFile;
	char* tokenState;
	xmlNodePtr cur;
	int shm;
	int successFlag = 0;
	
	/* Get shared memory segment for masterKey */
	shm = getAuthdata(1);
	if (shm == -1)
	{
		perror("Shared memory error");
		exit(1);
	}

	ctab = xmlParseFile(CONFIG_FILE);
	if (NULL == ctab)
	{
		printf("Configuration file loading error.\n");
	}
	else
	{
		if (argc < 2)
		{
			/* Get token configuration from cryptotab */
			cur = xmlDocGetRootElement(ctab);
			for (cur = cur->xmlChildrenNode; cur != NULL; cur = cur->next)
			{
				if (0 == xmlStrcmp(cur->name, (const char*) "token"))
				{
					tokenDev = xmlGetProp(cur, "dev");
					tokenFS = xmlGetProp(cur, "fstype");
					tokenDir = xmlGetProp(cur, "mnt");
					tokenFile = xmlGetProp(cur, "file");
					break;
				}
			}

			ret = getTokenConfig(tokenDev, tokenFS, tokenDir,
													 tokenFile, &tokenState);
			xmlFree(tokenDev);
			xmlFree(tokenFS);
			xmlFree(tokenDir);
			xmlFree(tokenFile);
			if (-1 == ret)
			{
				printf("Fatal error: %s\n", tokenState);
				error = 1;
			}
			else if (0 == ret)
			{
				printf("Error accessing token: %s\n", tokenState);
				error = 1;
			}
			else
				error = 0;
		}
		else
		{
			/* Get token configuration file from argv[1] */
			ctokenFile = argv[1];
			ctoken = xmlParseFile(ctokenFile);
			if (NULL == ctoken)
			{
				printf("Token configuration loading error.\n");
				error = 1;
			}
		}
		if (1 != error)
		{
			ret = promptForUser(&tUserNode, &dUserNode);
			if (1 == ret)
			{
				getPassphrase(&passphrase, "Enter passphrase: ");
				printf("Checking passphrase... ");
				fflush(stdout);
				ret = getUserTokenKey(&utk, NULL, tUserNode, passphrase);
				free(passphrase);
				if (-1 == ret)
				{
					printf(" bad.\n");
				}
				else
				{
					printf(" ok.\n");
					/* Decrypt masterKey using userTokenKey */
					ret = decryptMasterKey(&mk, utk, dUserNode);
					if (-1 == ret)
					{
						printf("Master key decryption failed.\n");
					}
					else
					{
						/* Copy masterKey to shared memory segment */
						for (i = 0; i < 128/8; i++)
							authdata[i] = mk[i];
						printf("Master key placed in shared memory.\n");
						successFlag = 1;
						free(mk);
					}
					free(utk); /* user key not needed now */
				}
			}
			xmlFreeDoc(ctoken);
		}
		xmlFreeDoc(ctab);
	}
	
	if (1 != successFlag)
	{
		/* Destroy shm segment */
		ret = shmdt(authdata);
		if (ret == -1)
		{
			perror("shmdt");
			exit(1);
		}

		ret = shmctl(shm, IPC_RMID, NULL);
		if (ret == -1)
		{
			perror("shmctl");
			exit(1);
		}
	}

	return error;
}

#include "all.h"

#include <stdio.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <stdlib.h>
#include "shell.h"
#include "cryptokencfg.h"
#include "tokencommon.h"
#include "globalvars.h"

int
createNewTUser(out_userNode, name)
	xmlNodePtr* out_userNode;
	char* name;
{
	xmlNodePtr cur, userNode;
	
	cur = xmlDocGetRootElement(ctoken);
	for (cur = cur->xmlChildrenNode; cur != NULL; cur = cur->next)
	{
		if (0 == xmlStrcmp(cur->name, "users"))
		{
			userNode = xmlNewChild(cur, NULL, "user", NULL);
			xmlSetProp(userNode, "name", name);
			*out_userNode = userNode;
			return 1;
		}
	}
	return -1;
}

void
removeAuthEntry(userNode)
	xmlNodePtr userNode;
{
	xmlNodePtr cur;
	/* Remove pbkdf2 and userkey nodes */
	for (cur = userNode->xmlChildrenNode; cur != NULL; cur = cur->next)
	{
		if (0 == xmlStrcmp(cur->name, "pbkdf2"))
		{
			xmlUnlinkNode(cur);
			xmlFreeNode(cur);
			break;
		}
	}
	for (cur = userNode->xmlChildrenNode; cur != NULL; cur = cur->next)
	{
		if (0 == xmlStrcmp(cur->name, "userkey"))
		{
			xmlUnlinkNode(cur);
			xmlFreeNode(cur);
			break;
		}
	}
	return;
}

/* Called by createAuthEntry to write prepared data to xml */
int
addAuthEntryXML(userNode, count, salt, key, magic)
	xmlNodePtr userNode;
	unsigned long count;
	u_int8_t* salt;
	u_int8_t* key;
	u_int8_t* magic;
{
	char* keyText;
	char* magicText;
	char* saltText;
	char* countText;
	xmlNodePtr userkeyNode, key128Node, pbkdf2Node, saltNode, magicNode;

	/* Convert encrypted key, magic and salt to hex */
	byte2hex(&keyText, key, 128/8);
	byte2hex(&saltText, salt, 64/8);
	byte2hex(&magicText, magic, 128/8);
	/* Convert iteration count to string */
	num2str(&countText, count);
	
	pbkdf2Node = xmlNewChild(userNode, NULL, "pbkdf2", NULL);
	xmlSetProp(pbkdf2Node, "iterations", countText);
	saltNode = xmlNewTextChild(pbkdf2Node, NULL, "salt", saltText);
	userkeyNode = xmlNewChild(userNode, NULL, "userkey", NULL);
	key128Node = xmlNewTextChild(userkeyNode, NULL, "key128", keyText);
	magicNode = xmlNewTextChild(userkeyNode, NULL, "encmagic", magicText);
	free(countText);
	free(saltText);
	free(keyText);
	return 1;
}

void
createAuthEntry(dkey, userNode, passphrase, count)
	u_int8_t* dkey;
	xmlNodePtr userNode;
	unsigned long count;
	char* passphrase;
{
	u_int8_t* salt;
	u_int8_t* ekey;
	u_int8_t* pkey;
	u_int8_t* emagic;
	int ret;
	AES_KEY ik;
	
	salt = malloc(64/8);
	ret = RAND_bytes(salt, 64/8);
	if (0 == ret)
	{
		printf("RAND_bytes: %lu\n", ERR_get_error());
		exit(1);
	}

	/* Derive passphrase key - pkey */
	ret = pkcs5_pbkdf2(&pkey, 128/8, passphrase,
										 strlen(passphrase), salt, 64/8, count);
	if (ret != 0)
	{
		printf("pbkdf2 error.\n");
		exit(1);
	}
	else
	{
		ekey = (u_int8_t*) malloc(128/8);
		/* Encrypt user token key with pkey */
		AES_set_encrypt_key(pkey, 128, &ik);
		AES_ecb_encrypt(dkey, ekey, &ik, AES_ENCRYPT);
						
		free(pkey);
		
		/* Encrypt magic string with dkey */
		emagic = (u_int8_t*) malloc(128/8);
		AES_set_encrypt_key(dkey, 128, &ik);
		AES_ecb_encrypt(MAGIC_STRING, emagic, &ik, AES_ENCRYPT);
	
		addAuthEntryXML(userNode, count, salt, ekey, emagic);

		free(emagic);
		free(salt);
		free(ekey);
	}

	return;
}

int
cAdd(arg)
	char* arg;
{
	char* rawName;
	char* name;
	char* rawICountText;
	char* iCountText;
	char* passphrase;
	char* passphraseVer;
	char answer;
	unsigned long iCount;
	u_int8_t* dkey;
	int ret, stop;
	xmlNodePtr userNode;
	
	printf("Please enter new user's information.\n");
	rawName = readline("User name: ");
	if ((NULL == rawName) || (0 == strcmp("", name = trim(rawName))))
	{
		printf("User name could not be empty.\n");
	}
	else
	{
		rawICountText = readline("Iteration count [65536]: ");
		stop = 0;
		if ((NULL == rawICountText) ||
				(0 == strcmp("", iCountText = trim(rawICountText))))
		{
			iCount = 65536;
		}
		else
		{
			ret = str2num(&iCount, iCountText);
			if (ret == -1)
			{
				printf("Bad format of iteration count.\n");
				stop = 1;
			}
		}
		free(rawICountText);
		if (stop != 1)
		{
			getPassphrase(&passphrase, "Passphrase: ");
			getPassphrase(&passphraseVer, "Verify passphrase: ");
			if (0 != strcmp(passphrase, passphraseVer))
			{
				printf("Passphrases do not match.\n");
			}
			else
			{
				answer=ynQuestion("Do you want to manually enter the key?",'n');
				if ('y' == answer)
				{
					printf("FIXME: Sorry, not yet implemented.\n");
				}
				/* else FIXME */
				{
					dkey = malloc(128/8);
					ret = RAND_bytes(dkey, 128/8);
					if (0 == ret)
					{
						printf("RAND_bytes: %lu\n", ERR_get_error());
						exit(1);
					}
					printf("Creating user... ");
					fflush(stdout);
					createNewTUser(&userNode, name);
					createAuthEntry(dkey, userNode, passphrase, iCount);
					printf("done.\n");
					free(dkey);
				}
			}
			free(passphrase);
			free(passphraseVer);
		}
	}
	free(rawName);
	
	return 1;
}


int
cPasswd(arg)
	char* arg;
{
	unsigned long ui;
	int ret;
	xmlNodePtr* utab;
	xmlNodePtr user;
	xmlChar* name;
	char* oldPassphrase;
	char* newPassphrase;
	char* newPassphraseVer;
	unsigned long count;
	u_int8_t* dkey;
	
	if (NULL == arg)
	{
		printf("User number as argument required.\n");
		return 1;
	}
	ret = str2num(&ui, arg);
	if (-1 == ret)
	{
		printf("Bad index '%s'.\n", arg);
		return 1;
	}
	
	fillUserTab(&utab, ctoken);
	
	ret = getNode(&user, utab, ui);
	if (-1 == ret)
	{
		printf("No such user.\n");
	}
	else
	{
		name = xmlGetProp(user, "name");
		printf("Changing passphrase for user '%s'.\n", name);
		getPassphrase(&oldPassphrase, "Old passphrase: ");
		printf("Checking passphrase... ");
		fflush(stdout);
		ret = getUserTokenKey(&dkey, &count, user, oldPassphrase);
		if (-1 == ret)
		{
			printf("bad.\n");
		}
		else
		{
			printf(" correct.\n");
			getPassphrase(&newPassphrase, "New passphrase: ");
			getPassphrase(&newPassphraseVer, "Verify new passphrase: ");
			if (0 != strcmp(newPassphrase, newPassphraseVer))
			{
				printf("New passphrases don't match.\n");
			}
			else
			{
				printf("Updating passphrase... ");
				fflush(stdout);
				removeAuthEntry(user);
				createAuthEntry(dkey, user, newPassphrase, count);
				printf("done.\n");
			}
			free(newPassphrase);
			free(newPassphraseVer);
			free(dkey);
		}
		free(oldPassphrase);
		xmlFree(name);
	}
	free(utab);
	return 1;
}

int
cShowkey(arg)
	char* arg;
{
	unsigned long ui;
	int ret, i;
	xmlNodePtr* utab;
	xmlNodePtr user;
	xmlChar* name;
	char* prompt;
	char* tmp;
	char* passphrase;
	u_int8_t* dkey;
	
	if (NULL == arg)
	{
		printf("User number as argument required.\n");
		return 1;
	}
	ret = str2num(&ui, arg);
	if (-1 == ret)
	{
		printf("Bad index '%s'.\n", arg);
		return 1;
	}
	
	fillUserTab(&utab, ctoken);
	
	ret = getNode(&user, utab, ui);
	if (-1 == ret)
	{
		printf("No such user.\n");
	}
	else
	{
		name = xmlGetProp(user, "name");
		xstrcat(&tmp, "Enter passphrase for user '", name);
		xstrcat(&prompt, tmp, "': ");
		free(tmp);

		getPassphrase(&passphrase, prompt);
		free(prompt);
		printf("Checking passphrase... ");
		fflush(stdout);
		ret = getUserTokenKey(&dkey, NULL, user, passphrase);
		if (-1 == ret)
		{
			printf("bad.\n"); 
		}
		else
		{
			printf("correct.\n");
			printf("Token key for user '%s':\n\t", name);
			for (i = 0; i < 128/8; i++)
			{
				if (i == 128/8/2)
					printf(" ");
				printf(" %.2x", dkey[i]);
			}
			printf("\n");
			free(dkey);
		}
		
		free(passphrase);
		xmlFree(name);
	}
	free(utab);
	return 1;
}

int
cRemove(arg)
	char* arg;
{
	unsigned long ui;
	int ret;
	xmlNodePtr* utab;
	xmlNodePtr user;
	char answer;
	xmlChar* name;
	
	if (NULL == arg)
	{
		printf("User number as argument required.\n");
		return 1;
	}
	ret = str2num(&ui, arg);
	if (-1 == ret)
	{
		printf("Bad index '%s'.\n", arg);
		return 1;
	}
	
	fillUserTab(&utab, ctoken);
	
	ret = getNode(&user, utab, ui);
	if (-1 == ret)
	{
		printf("No such user.\n");
	}
	else
	{
		name = xmlGetProp(user, "name");
		printf("You are going to remove user '%s' from token.\n", name);
		answer = ynQuestion("Are you sure?", 'n');
		if ('y' == answer)
		{
			xmlUnlinkNode(user);
			xmlFreeNode(user);
			printf("User '%s' removed from token.\n", name);
		}
		xmlFree(name);
	}
	free(utab);
	return 1;
}

int
cList(arg)
	char* arg;
{
	xmlNodePtr* utab;
	int i;
	fillUserTab(&utab, ctoken);
	if (NULL == utab[0])
		printf("No user entries in token configuration file.\n");
	else
	{
		printf("  #\r");
		printf(" \tName\r\n");
		for (i = 0; NULL != utab[i]; i++)
		{
			printUserLine(i, utab[i]);
		}
	}
	free(utab);

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
		file = ctokenFile;
	
	printf("Configuration will be written to '%s'.\n", file);
	answer = ynQuestion("Are you sure?", 'n');
	if (answer == 'y')
	{
		ret = xmlSaveFormatFile(file, ctoken, 1);
		if (-1 == ret)
			printf("Writing configuration to file '%s' failed.\n", file);
		else
			printf("Configuration saved to '%s'\n", file);
	}
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
cQuit(arg)
	char* arg;
{
	return -1;
}

Command commands[] =
{
	{"showkey", cShowkey, "Show key for user n", "n"},
	{"passwd", cPasswd, "Change passphrase for user n", "n"},
	{"remove", cRemove, "Remove user entry", "n"},
	{"add", cAdd, "Add new user", ""},
	{"list", cList, "List user entries", ""},
	{"save", cSave, "Save token configuration", "[file]"},
	{"help", cHelp, "Display help", ""},
	{"quit", cQuit, "Quit program", ""},
	{(char*) NULL, (rl_icpfunc_t*) NULL, (char*) NULL}
};


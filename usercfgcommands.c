#include "all.h"

#include <stdio.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <stdlib.h>
#include "shell.h"
#include "tokencommon.h"
#include "globalvars.h"

int
addUserToCtabXML(name, emk, emagic)
	char* name;
	u_int8_t* emk;
	u_int8_t* emagic;
{
	char* emkText;
	char* emagicText;
	xmlNodePtr userNode, key128Node, emagicNode, cur;

	byte2hex(&emagicText, emagic, 128/8);
	byte2hex(&emkText, emk, 128/8);
	
	cur = xmlDocGetRootElement(ctab);
	for (cur = cur->xmlChildrenNode; NULL != cur; cur = cur->next)
	{
		if (0 == xmlStrcmp(cur->name, "users"))
		{
			userNode = xmlNewChild(cur, NULL, "user", NULL);
			xmlSetProp(userNode, "name", name);
			key128Node = xmlNewTextChild(userNode, NULL, "key128", emkText);
			emagicNode = xmlNewTextChild(userNode, NULL, "encmagic",
																	 emagicText);
			break;
		}
	}
	free(emkText);
	free(emagicText);
	return 1;
}

void
addUserToCtab(name, utk)
	char* name;
	u_int8_t* utk;
{
	u_int8_t* emk;
	u_int8_t* emagic;
	AES_KEY ik;
	emk = (u_int8_t*) malloc(128/8);
	emagic = (u_int8_t*) malloc(128/8);
	
	/* Encrypt masterkey with user token key */
	AES_set_encrypt_key(utk, 128, &ik);
	AES_ecb_encrypt(authdata, emk, &ik, AES_ENCRYPT);
	
	/* Encrypt magic string with user token key */
	AES_ecb_encrypt(MAGIC_STRING, emagic, &ik, AES_ENCRYPT);
	
	addUserToCtabXML(name, emk, emagic);
	
	free(emagic);
	free(emk);

	return;
}

int
cUSourceT(arg)
	char* arg;
{
	char* dev;
	char* fs;
	xmlNodePtr cur;
	if (NULL != cryptokenFile)
		free(cryptokenFile);

	cryptokenFile = NULL;
	cur = xmlDocGetRootElement(ctab);
	for (cur = cur->xmlChildrenNode; NULL != cur; cur = cur->next)
	{
		if (0 == xmlStrcmp(cur->name, "token"))
		{
			dev = xmlGetProp(cur, "dev");
			fs = xmlGetProp(cur, "fstype");
			printf("Using token at '%s' (%s filesystem) as users source.\n",
				 			dev, fs);
			xmlFree(dev);
			xmlFree(fs);
			break;
		}
	}
	return 1;
}

int
cUSourceF(arg)
	char* arg;
{
	if (NULL == arg)
	{
		printf("File name as argument required.\n");
	}
	else
	{
		if (NULL != cryptokenFile)
			free(cryptokenFile);

		cryptokenFile = strdup(arg);
		printf("Using '%s' file as users source.\n", cryptokenFile);
	}
	return 1;
}

int
cGrant(arg)
	char* arg;
{
	xmlNodePtr userNode, cur;
	xmlChar* tokenDev;
	xmlChar* tokenFS;
	xmlChar* tokenDir;
	xmlChar* tokenFile;
	char* tokenState;
	int ret;
	int error = 0;
	char* passphrase;
	u_int8_t* utk;
	xmlChar* name;

	if (NULL == cryptokenFile)
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
		ctoken = xmlParseFile(cryptokenFile);
		if (NULL == ctoken)
		{
			printf("Token configuration loading error.\n");
			error = 1;
		}
	}
	if (1 != error)
	{
		ret = promptForUser(&userNode, NULL);
		if (1 == ret)
		{
			getPassphrase(&passphrase, "Enter passphrase: ");
			printf("Checking passphrase... ");
			fflush(stdout);
			ret = getUserTokenKey(&utk, NULL, userNode, passphrase);
			free(passphrase);
			if (-1 == ret)
			{
				printf(" bad.\n");
			}
			else
			{
				printf(" ok.\n");
				/* Encrypt masterKey using userTokenKey */
				name = xmlGetProp(userNode, "name");
				addUserToCtab(name, utk);
				free(utk); /* user key not needed now */
				printf("Access granted for user '%s'.\n", name);
				xmlFree(name);
			}
		}
		xmlFreeDoc(ctoken);
	}
	return 1;
}

int
cRevoke(arg)
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
	
	fillUserTab(&utab, ctab);
	
	ret = getNode(&user, utab, ui);
	if (-1 == ret)
	{
		printf("No such user.\n");
	}
	else
	{
		name = xmlGetProp(user, "name");
		printf("You are going to cancel access for user '%s'.\n", name);
		answer = ynQuestion("Are you sure?", 'n');
		if ('y' == answer)
		{
			xmlUnlinkNode(user);
			xmlFreeNode(user);
			printf("Access for user '%s' was cancelled.\n", name);
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
	fillUserTab(&utab, ctab);
	if (NULL == utab[0])
		printf("No users entries defined in configuration file.\n");
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
	{"usourcef", cUSourceF, "Read user entries from file", "[file]"},
	{"usourcet", cUSourceT, "Read user entries from token", ""},
	{"revoke", cRevoke, "Revoke access for user n", "n"},
	{"grant", cGrant, "Grant access for user",
	 ""},
	{"list", cList, "List users with access permission", ""},
	{"save", cSave, "Save cryptotab configuration", "[file]"},
	{"help", cHelp, "Display help", ""},
	{"quit", cQuit, "Quit program", ""},
	{(char*) NULL, (rl_icpfunc_t*) NULL, (char*) NULL}
};


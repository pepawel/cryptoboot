#include "all.h"

#include <stdio.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <stdlib.h>
#include "shell.h"
#include "util.h"
#include "globalvars.h"

void
fillUserTab(out_tab, doc)
	xmlNodePtr** out_tab;
	xmlDocPtr doc;
{
	xmlNodePtr user, cur, root;
	xmlNodePtr* tab;
	int i;
	
	/* Count elements */
	root = xmlDocGetRootElement(doc);
	i = 0;
	for (cur = root->xmlChildrenNode; cur != NULL; cur = cur->next)
	{
		if (0 == xmlStrcmp(cur->name, "users"))
		{
			for (user = cur->xmlChildrenNode; user != NULL; user = user->next)
				if (0 == xmlStrcmp(user->name, "user"))
					i++;
			break;
		}
	}

	tab = malloc(sizeof(xmlNodePtr) * (i + 1));
	
	i = 0;
	for (cur = root->xmlChildrenNode; cur != NULL; cur = cur->next)
	{
		if (0 == xmlStrcmp(cur->name, "users"))
		{
			for (user = cur->xmlChildrenNode; user != NULL; user = user->next)
				if (0 == xmlStrcmp(user->name, "user"))
				{
					tab[i]= user;
					i++;
				}
			break;
		}
	}
	
	tab[i] = (xmlNodePtr) NULL;
	
	*out_tab = tab;
	
	return;
}

/* If count not null, function puts in it iteration count */
int
getUserTokenKey(out_key, out_count, userNode, passphrase)
	u_int8_t** out_key;
	unsigned long* out_count;
	xmlNodePtr userNode;
	char* passphrase;
{
	u_int8_t* pkey; /* passphrase derived key */
	u_int8_t* ukey; /* decrypted, userTokenKey */
	u_int8_t* ekey; /* encrypted, userTokenKey */
	u_int8_t* salt;
	u_int8_t* emagicStored;
	u_int8_t* emagicComputed;
	xmlChar* saltText;
	xmlChar* ekeyText;
	xmlChar* emagicTextStored;
	int saltlen;
	int iterationCount;
	xmlChar* iterationCountText;
	xmlNodePtr cur, bcur;
	int ret;
	AES_KEY ik;
	int result;

	result = -1;
	
	/* Get pbkdf2 arguments and key from xml node */
	/* Find pbkdf2 tag */
	for (bcur = userNode->xmlChildrenNode; bcur != NULL; bcur= bcur->next)
	{
		if (0 == xmlStrcmp(bcur->name, (const xmlChar*) "pbkdf2"))
		{
			/* Get iteration count */
			iterationCountText = xmlGetProp(bcur, "iterations");
			iterationCount = atoi(iterationCountText);
			xmlFree(iterationCountText);

			/* Get salt and salt length in bytes */
			for (cur = bcur->xmlChildrenNode; cur != NULL; cur = cur->next)
			{
				if (0 == xmlStrcmp(cur->name, (const xmlChar*) "salt"))
				{
					saltText=xmlNodeListGetString(ctoken,cur->xmlChildrenNode,1);
					cleanWhiteSpace((char**)(&saltText));

					/* Salt is in hex-string format, so its length
					 * in bytes is two times smaller. XML Schema's job
					 * is to warn if salt is in bad format
					 */				
					saltlen = strlen(saltText) / 2;
					/* Convert salt to byte tab */
					hex2byte(&salt, saltText, saltlen);
					xmlFree(saltText);
					break;
				}
			}
		}
		else if (0 == xmlStrcmp(bcur->name, (const xmlChar*) "userkey"))
		{
			for (cur = bcur->xmlChildrenNode; cur != NULL; cur = cur->next)
			{
				if (0 == xmlStrcmp(cur->name, (const xmlChar*) "key128"))
				{
					ekeyText = xmlNodeListGetString(ctoken,
				 																  cur->xmlChildrenNode, 1);
					cleanWhiteSpace((char**)(&ekeyText));

					/* Convert key to byte tab */
					hex2byte(&ekey, ekeyText, 128/8);
					xmlFree(ekeyText);
				}
				else if (0 == xmlStrcmp(cur->name, (const xmlChar*) "encmagic"))
				{
					emagicTextStored = xmlNodeListGetString(ctoken,
				 																  cur->xmlChildrenNode, 1);
					cleanWhiteSpace((char**)(&emagicTextStored));

					/* Convert key to byte tab */
					hex2byte(&emagicStored, emagicTextStored, 128/8);
					xmlFree(emagicTextStored);
				}

			}
		}
	}

	/* Transform passphrase, salt and interation count into pkey
	 * using pbkdf2 as key derivation function */
	ret = pkcs5_pbkdf2(&pkey, 128/8, passphrase, strlen(passphrase),
										 salt, saltlen, iterationCount);
	free(salt);
	if (ret != 0)
	{
		printf("pbkdf2 error.\n");
		exit(1);
	}
	else
	{
		ukey = (u_int8_t*) malloc(128/8);
		/* Dekrypt userTokenKey using pkey as a key */
		AES_set_decrypt_key(pkey, 128, &ik);
		/* FIXME: current implementation decrypts data only
		 * 				one-block long - if user wants longer data
		 * 				it will not work.
		 */
		AES_ecb_encrypt(ekey, ukey, &ik, AES_DECRYPT);
		free(ekey);
		free(pkey);
		/* Encrypt magic string with ukey to see if passphrase is correct */
		emagicComputed = (u_int8_t*) malloc(128/8);
		AES_set_encrypt_key(ukey, 128, &ik);
		AES_ecb_encrypt(MAGIC_STRING, emagicComputed, &ik, AES_ENCRYPT);
		if (0 == memcmp(emagicComputed, emagicStored, 128/8))
		{
			*out_key = ukey;
			if (NULL != out_count)
				*out_count = iterationCount;
			result = 1;
		}
		free(emagicStored);
		free(emagicComputed);
	}
	
	return result;
}

/* Returns 1 if correct token detected, 0 if not, -1 if fatal error */
int
getTokenConfig(dev, type, mnt, filename, out_result)
	char* dev;
	char* type;
	char* mnt;
	char* filename;
	char** out_result;
{
	char* name;
	char* tmpname;
	xmlDocPtr tmpDoc;
	int ret, fd, result;
	/* Construct full name of token config file */
	xstrcat(&tmpname, mnt, "/");
	xstrcat(&name, tmpname, filename);
	free(tmpname);

	/* Try to open device to see if it is inserted */
	fd = open(dev, O_RDONLY);
	if (fd == -1)
	{
		result = 0;
		if (errno == EACCES)
			*out_result = "permission denied";
		else
			*out_result = "not detected";
	}
	else
	{
		ret = close(fd);
		if (-1 == ret)
		{
			*out_result = "closing device failed";
			result = -1;
		}
		else
		{
			/* Try to mount device readonly using given fstype */
			ret = mount(dev, mnt, type, 0xC0ED0000 | MS_RDONLY, NULL);
			if (ret == -1)
			{
				*out_result = "mounting error";
				result = 0;
			}
			else
			{
				/* Check existence of token config file */
				fd = open(name, O_RDONLY);
				if (fd == -1) 
				{
					ret = umount(mnt);
					if (ret == -1)
					{
						*out_result = "umounting error";
						result = -1;
					}
					else
					{
						*out_result = "config file not found";
						result = 0;
					}
				}
				else
				{
					ret = close(fd);
					if (-1 == ret)
					{
						*out_result = "closing file failed";
						result = -1;
					}
					else
					{
						/* Parse token config file */
						tmpDoc = xmlParseFile(name);
						if (NULL == tmpDoc)
						{
							ret = umount(mnt);
							if (ret == -1)
							{
								*out_result = "umounting error";
								result = -1;
							}
							else
							{
								*out_result = "config file parsing error";
								return 0;
							}
						}
						else
						{
							/* Umount fs */
							ret = umount(mnt);
							if (-1 == ret)
							{
								*out_result = "umounting error";
								result = -1;
							}
							else
							{
								/* Return xmlDocPtr */
								ctoken = tmpDoc;
								*out_result = "detected";
								result = 1;
							}
						}
					}
				}
			}
		}
	}
	free(name);
	return result;
}

/* Joins tokenTab with diskTab on encmagic */
int
joinUNodeTabs(out_tTab, out_dTab, tokenTab, diskTab)
	xmlNodePtr** out_tTab;
	xmlNodePtr** out_dTab;
	xmlNodePtr* tokenTab;
	xmlNodePtr* diskTab;
{
	xmlChar* temagic;
	xmlChar* demagic;
	int i;
	int j;
	int tokenCount, diskCount, tabIndex;
	xmlNodePtr* ttab;
	xmlNodePtr* dtab;
	xmlNodePtr cur;
	size_t tabMaxSize;
	
	
	for (i = 0; NULL != tokenTab[i]; i++);
	tokenCount = i;
	for (i = 0; NULL != diskTab[i]; i++);
	diskCount = i;

	tabMaxSize = sizeof(xmlNodePtr) * (tokenCount + diskCount + 1);
	
	ttab = (xmlNodePtr*) malloc(tabMaxSize);
	dtab = (xmlNodePtr*) malloc(tabMaxSize);
	tabIndex = 0;
	for (i = 0; NULL != tokenTab[i]; i++)
		for (j = 0; NULL != diskTab[j]; j++)
		{
			for (cur = tokenTab[i]->xmlChildrenNode;
					 NULL != cur; cur = cur->next)
			{
				if (0 == xmlStrcmp(cur->name, "userkey"))
				{
					for (cur = cur->xmlChildrenNode;
							 NULL != cur; cur = cur->next)
					{
						if (0 == xmlStrcmp(cur->name, "encmagic"))
						{
							temagic = xmlNodeListGetString(ctoken,
												cur->xmlChildrenNode, 1);
							break;
						}
					}
					break;
				}
			}
			
			for (cur = diskTab[j]->xmlChildrenNode;
					 NULL != cur; cur = cur->next)
			{
				if (0 == xmlStrcmp(cur->name, "encmagic"))
				{
					demagic = xmlNodeListGetString(ctab,
										cur->xmlChildrenNode, 1);
					break;
				}
			}

			cleanWhiteSpace((char**) (&temagic));
			cleanWhiteSpace((char**) (&demagic));
			if (0 == xmlStrcmp(temagic, demagic))
			{
				ttab[tabIndex] = tokenTab[i];
				dtab[tabIndex] = diskTab[j];
				tabIndex++;
			}
			xmlFree(temagic);
			xmlFree(demagic);
		}
	
	ttab = (xmlNodePtr*) realloc(ttab, sizeof(xmlNodePtr) * tabIndex);
	dtab = (xmlNodePtr*) realloc(dtab, sizeof(xmlNodePtr) * tabIndex);
	
	*out_tTab = ttab;
	*out_dTab = dtab;
	
	return tabIndex;
}

/* We do not verify encmagic in <user> node, because it is
 * the same as in token. It is verified in getUserTokenKey.
 * Last but not least - users with encmagic mismatch are not
 * listed in user select window. */
int
decryptMasterKey(out_masterKey, userTokenKey, userNode)
	u_int8_t** out_masterKey;
	u_int8_t* userTokenKey;
	xmlNodePtr userNode;
{
	u_int8_t* mkey;
	u_int8_t* ekey;
	u_int8_t* emagicStored;
	u_int8_t* emagicCurrent;
	xmlChar* ekeyText;
	xmlChar* emagicStoredText;
	AES_KEY ik;
	xmlNodePtr cur, root;
	int ret;
	int fresult = -1;
	
	/* Get encrypted master key */
	for (cur = userNode->xmlChildrenNode; cur != NULL; cur=cur->next)
	{
		if (0 == xmlStrcmp(cur->name, "key128"))
		{
			ekeyText = xmlNodeListGetString(ctab, cur->xmlChildrenNode, 1);
			cleanWhiteSpace((char**)(&ekeyText));
			ret = hex2byte(&ekey, ekeyText, 128/8);
			if (ret == -1)
			{
				printf("Internal error.\n");
				exit(1);
			}
			else
			{
				/* Decrypt master key using userTokenKey */
				AES_set_decrypt_key(userTokenKey, 128, &ik);
	
				mkey = malloc(128/8);
				
				/* FIXME: current implementation decrypts data only
				 * 				one-block long - if user wants longer data
				 * 				it will not work.
				 */
				AES_ecb_encrypt(ekey, mkey, &ik, AES_DECRYPT);

				free(ekey);
			
				/* Check encmagic for master key */
				root = xmlDocGetRootElement(ctab);
				for (cur = root->xmlChildrenNode; NULL != cur; cur = cur->next)
				{
					if (0 == xmlStrcmp(cur->name, "encmagic"))
					{
						emagicStoredText = xmlNodeListGetString(ctab,
															 cur->xmlChildrenNode, 1);
						cleanWhiteSpace((char**) (&emagicStoredText));
						emagicStored = (u_int8_t*) malloc(128/8);
						hex2byte(&emagicStored, emagicStoredText, 128/8);
						xmlFree(emagicStoredText);
						
						emagicCurrent = (u_int8_t*) malloc(128/8);
						AES_set_encrypt_key(mkey, 128, &ik);
						AES_ecb_encrypt(MAGIC_STRING,emagicCurrent,&ik,AES_ENCRYPT);
						
						if (0 == memcmp(emagicCurrent, emagicStored, 128/8))
						{
							(*out_masterKey) = mkey;
							fresult = 1;
						}
						free(emagicCurrent);
						free(emagicStored);
						break;
					}
				}
			}
			xmlFree(ekeyText);
			break;
		}
	}
	
	return fresult;
}

/* When out_dUserNode is NULL then user will choose from token
 * users - even if these users are not it ctab;
 * of course no ctab node will be returned in out_dUserNode then */
int
promptForUser(out_tUserNode, out_dUserNode)
	xmlNodePtr* out_tUserNode;
	xmlNodePtr* out_dUserNode;
{
	xmlNodePtr* tokenTab;
	xmlNodePtr* diskTab;
	xmlNodePtr* dUNodeTab;
	xmlNodePtr* tUNodeTab;
	int ret, i, userCount;
	int result = -1;
	xmlChar* name;
	unsigned long sel;
	char* selText;
	
	
	fillUserTab(&tokenTab, ctoken);
	fillUserTab(&diskTab, ctab);
	if (NULL != out_dUserNode)
	{
		userCount = joinUNodeTabs(&tUNodeTab,&dUNodeTab,tokenTab,diskTab);
	}
	else
	{
		for (i = 0; NULL != tokenTab[i]; i++);
		userCount = i;
		fillUserTab(&dUNodeTab, ctoken);
		fillUserTab(&tUNodeTab, ctoken);
	}
		
	if (0 == userCount)
	{
		for (i = 0; NULL != tokenTab[i]; i++);
		if (0 == i)
		{
			printf("No users on token found.\n");
		}
		else
		{
			printf("No user on token is allowed to access this machine.\n");
		}
		result = -1;
	}
	else if (1 == userCount)
	{
		name = xmlGetProp(tUNodeTab[0], "name");
		printf("User '%s' found.\n", name);
		xmlFree(name);
		*out_tUserNode = tUNodeTab[0];
		if (NULL != out_dUserNode)
			*out_dUserNode = dUNodeTab[0];
		result = 1;
	}
	else
	{
		printf("  #\tUser\n");
		for (i = 0; i < userCount; i++)
		{
			name = xmlGetProp(tUNodeTab[i], "name");
			printf(" %2d\t%s\n", i, name);
			xmlFree(name);
		}
		selText = readline("Select user: ");
		if (NULL != selText)
		{
			ret = str2num(&sel, selText);
			if (-1 != ret)
			{
				if ((sel < userCount) && (sel >= 0))
				{
					*out_tUserNode = tUNodeTab[sel];
					if (NULL != out_dUserNode)
						*out_dUserNode = dUNodeTab[sel];
					name = xmlGetProp(tUNodeTab[sel], "name");
					printf("You have selected '%s'.\n", name);
					xmlFree(name);
					result = 1;
				}
				else
					printf("No such user.\n");
			}
			else
				printf("Bad index '%s'.\n", selText);
			free(selText);
		}
		else
			printf("\n");
	}
	
	free(diskTab);
	free(tokenTab);
	free(dUNodeTab);
	free(tUNodeTab);
	return result;
}

/* Prints index and user name from node tab entry given by this index */
/* If user name is empty prints "-" (usefull, when someone don't want
 * to save user names in cryptotab) */
void
printUserLine(index, node)
	int index;
	xmlNodePtr node;
{
	xmlChar* name;

	name = xmlGetProp(node, "name");
	if (NULL != name)
	{
		printf(" %2d\t%s\n", index, name);
		xmlFree(name);
	}
	else
		printf(" %2d\t%s\n", index, "-");
		
	return;
}


#include "all.h"

#include <stdio.h>
#include <stdlib.h>
#include "util.h"
#include "globalvars.h"

int
checkMKEncMagic()
{
	u_int8_t* emagicCurrent;
	u_int8_t* emagicStored;
	AES_KEY ik;
	xmlNodePtr root;
	xmlNodePtr emagicNode;
	xmlChar* emagicStoredText;
	xmlChar* emagicCurrentText;
	int ret = -1;
	
	/* Encrypt magic string with current master key */
	emagicCurrent = (u_int8_t*) malloc(128/8);
	AES_set_encrypt_key(authdata, 128, &ik);
	AES_ecb_encrypt(MAGIC_STRING, emagicCurrent, &ik, AES_ENCRYPT);
	
	/* Find encmagic element in cryptotab */
	root = xmlDocGetRootElement(ctab);
	for (emagicNode = root->xmlChildrenNode;
			 NULL != emagicNode; emagicNode = emagicNode->next)
	{
		if (0 == xmlStrcmp(emagicNode->name, "encmagic"))
			break;
	}
	if (NULL != emagicNode)
	{
		/* encmagic was found - compare it with current, computed value */
		emagicStoredText = xmlNodeListGetString(ctab,
											 emagicNode->xmlChildrenNode, 1);
		cleanWhiteSpace((char**) (&emagicStoredText));
		emagicStored = (u_int8_t*) malloc(128/8);
		hex2byte(&emagicStored, emagicStoredText, 128/8);
		xmlFree(emagicStoredText);

		if (0 != memcmp(emagicCurrent, emagicStored, 128/8))
		{
			/* encmagic mismatch! */
			printf("Encmagic stored in cryptotab and value computed from master key are not equal.\n");
			ret = -1;
		}
		else
			ret = 1;
		free(emagicStored);
	}
	else
	{
		/* encmagic not found - we need to create one and inform user */
		byte2hex((char**) (&emagicCurrentText), emagicCurrent, 128/8);
		emagicNode = xmlNewTextChild(root, NULL, "encmagic",
																 emagicCurrentText);
		xmlFree(emagicCurrentText);
		printf("Created encmagic. Type 'save' to update cryptotab.\n");
		ret = 1;
	}
	
	free(emagicCurrent);
	return ret;
}

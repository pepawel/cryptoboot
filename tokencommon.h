#ifndef _TOKENCOMMON_H_
#define _TOKENCOMMON_H_

void
fillUserTab(xmlNodePtr** out_tab, xmlDocPtr doc);

int
getUserTokenKey(u_int8_t** out_key,	unsigned long* out_count,
								xmlNodePtr userNode, char* passphrase);
int
getTokenConfig(char* dev,	char* type,	char* mnt, char* filename,
							 char** out_result);
int
joinUNodeTabs(xmlNodePtr** out_fTab, xmlNodePtr** out_sTab,
							xmlNodePtr* firstTab, xmlNodePtr* secondTab);
int
decryptMasterKey(u_int8_t** out_masterKey, u_int8_t* userTokenKey,
								 xmlNodePtr userNode);
int
promptForUser(xmlNodePtr* out_tUserNode, xmlNodePtr* out_dUserNode);
void
fillUserTab(xmlNodePtr** out_tab, xmlDocPtr doc);
void
printUserLine(int index, xmlNodePtr node);

#endif

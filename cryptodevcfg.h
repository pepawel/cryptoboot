#ifndef _CRYPTODEVCFG_H_
#define _CRYPTODEVCFG_H_

int
loopaesGetMultiKey(u_int8_t** out_dmk, xmlNodePtr device);
int
loopaesDetachDevice(char* loop);
int
loopaesSetupDevice(u_int8_t* mk,char* src, char* dst,	char** out_error);
int
fillDeviceTab(xmlNodePtr** out_tab);

#endif


#ifndef _UTIL_H_
#define _UTIL_H_

void
byte2hex(char** out_str, u_int8_t* tab, int len);
int
hex2byte(u_int8_t** out_tab, char* string, int len);
void
cleanWhiteSpace(char** out_str);
char*
trim (char *string);
void
split(char** out_one, char** out_two, char* str);
char
ynQuestion(char* prompt, char defAnswer);
int
str2num(unsigned long* out_d, char* str);
void
num2str(char** out_str,	unsigned long num);
int
xstrcat(char** out_str, char* first, char* second);
int
getNode(xmlNodePtr* out_node,	xmlNodePtr* ntab,	int ni);
void
getPassphrase(char** out_p,	char* prompt);

#endif


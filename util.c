#include "all.h"
#include <readline/readline.h>
#include <readline/history.h>
#include <stdio.h>
#include <termios.h>

/* len - length of tab */
void
byte2hex(out_str, tab, len)
	char** out_str;
	u_int8_t* tab;
	int len;
{
	char* str;
	int i;
	
	str = (char*) malloc(2*len + 1);
	if (NULL == str)
	{
		printf("Memory allocation error.\n");
		exit(1);
	}
	for (i = 0; i < len; i++)
	{
		sprintf(str + i*2, "%.2x", tab[i]);
	}
	*out_str = str;
	return;
}

/* len - length of returned tab FIXME: not needed? len=strlen(string) */
int
hex2byte(out_tab, string, len)
	u_int8_t** out_tab;
	char* string;
	int len;
{
	u_int8_t* tab;
	int i;
	char c;
	int d;
	tab = (u_int8_t*) malloc(len);
	
	for (i = 0; i < (len * 2); i++)
	{
		c = string[i];
		if ((c >= '0') && (c <= '9'))
			d = c - '0';
		else if ((c >= 'a') && (c <= 'f'))
			d = c - 'a' + 10;
		else if ((c >= 'A') && (c <= 'F'))
			d = c - 'A' + 10;
		else
		{
			free(tab);
			return -1;
		}
		if ((i % 2) == 0)
			tab[i/2] = d * 16;
		else
			tab[i/2] += d;
	}
	*out_tab = tab;
	return 1;
}

/* Warning - function operates only on dynamic strings */
void
cleanWhiteSpace(out_str)
	char** out_str;
{
	char* str;
	char* org;
	int i, j;
	
	org = *out_str;
	str = malloc(strlen(org) + 1);
	
	j = 0;
	for(i = 0; i < strlen(org); i++)
	{
		if (!((org[i] == ' ')  || (org[i] == '\n') ||
				 (org[i] == '\t') || (org[i] == '\r')))
		{
			str[j] = org[i];
			j++;
		}
	}
	str[j] = '\0';
	str = (char*) realloc(str, j + 1);
	if (str == NULL)
	{
		printf("Memory realocation failed.\n");
		exit(1);
	}
	
	free(org);
	*out_str = str;
}

/* Strip whitespace from the start and end of STRING.  Return a pointer
   into STRING. */
char *
trim (string)
     char *string;
{
	int len, i, start; 

	len = strlen(string);

	start = 0;
	for (i = 0; i < len; i++)
	{
		if ((string[i] == ' ') || (string[i] == '\t'))
			start++;
		else
			break;
	}

	if (i == len)
	{
		string[0] = '\0';
		return string;
	}
	
	for (i = len - 1; i >= 0; i--)
	{
		if ((string[i] == ' ') || (string[i] == '\t'))
			string[i] = '\0'; 
		else
			break;
	}
	
  return string + start;
}

void
split(out_one, out_two, str)
	char** out_one;
	char** out_two;
	char* str;
{
	int i, len;
	int flag;
	
	*out_one = str;
	*out_two = NULL;
	len = strlen(str);
	flag = 0;
	for (i = 0; i < len; i++)
	{
		if ((str[i] == ' ') || (str[i] == '\t'))
		{
			if (flag == 0)
			{
				flag = 1;
				str[i] = '\0';
			}
			else if (flag == 2)
			{
				str[i] = '\0';
				break;
			}
		}
		else
		{
			if (flag == 1)
			{
				*out_two = str + i;
				flag = 2;
			}
		}
	}
	return;
}

char
ynQuestion(prompt, defAnswer)
	char* prompt;
	char defAnswer;
{
	char* a;
	char* p;
	p = malloc(strlen(prompt) + 1 + 6);
	sprintf(p, "%s [%c]: ", prompt, defAnswer);
	/* FIXME: disable completion and history browsing */
	a = readline(p);
	if (NULL == a)
	{
		free(p);
		printf("\n");
		return defAnswer;
	}
	else if (0 == strcmp(a, "y"))
	{
		free(p);
		free(a);
		return 'y';
	}
	else if (0 == strcmp(a, "n"))
	{
		free(p);
		free(a);
		return 'n';
	}
	else
	{
		free(a);
		free(p);
		return defAnswer;
	}
}

int
str2num(out_d, str)
	unsigned long* out_d;
	char* str;
{
	int i;
	if (str == NULL) return -1;
	for (i = 0; i < strlen(str); i++)
		if (0 == isdigit(str[i])) return -1;
	*out_d = atol(str);
	return 1;
}

void
num2str(out_str, num)
	char** out_str;
	unsigned long num;
{
	char str[32];
	sprintf(str, "%lu", num);
	*out_str = strdup(str);
	return;
}

int
xstrcat(out_str, first, second)
	char** out_str;
	char* first;
	char* second;
{
	char* str;
	
	str = (char*) malloc(strlen(first) + strlen(second) + 1);
	if (NULL == str)
		return -1;
	sprintf(str, "%s%s", first, second);
	*out_str = str;
	return 1;
}


int
getNode(out_node, ntab, ni)
	xmlNodePtr* out_node;
	xmlNodePtr* ntab;
	int ni;
{
	int i;
	xmlNodePtr node;
	i = 0;
	for (;;)
	{
		node = ntab[i];
		if (node == NULL) return -1;
		if (ni == i)
		{
			*out_node = node;
			return 1;
		}
		i++;
	}
	return 1;
}

/* FIXME: turn off readline features such as completion, history etc.
 *        drop readline and get something better suited for
 *        passphrase reading - see "openssl passwd" source code */
void
getPassphrase(out_p, prompt)
	char** out_p;
	char* prompt;
{
	struct termios new, old;
	char* str;
	int fd;
	
	fd = 0; /* fileno(stdin); */
	
	/* Turn echo off and fail if we can't do it */
	if (0 != tcgetattr(fd, &old))
	{
		printf("Could not get terminal attributes.\n");
		exit(1);
	}
	
	new = old;
	new.c_lflag &= ~ECHO;
	if (0 != tcsetattr(fd, TCSAFLUSH, &new))
	{
		printf("Could not set terminal attributes.\n");
		exit(1);
	}
	
	str = readline(prompt);
	if (NULL == str)
		*out_p = strdup("");
	else
		*out_p = str;
	
	tcsetattr (fd, TCSAFLUSH, &old);
	printf("\n");
	
	return;
}


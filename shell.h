#ifndef _SHELL_H_
#define _SHELL_H_

typedef struct
{
	char* name;
	rl_icpfunc_t* func;
	char* doc;
	char* args;
} Command;

extern Command commands[];

char* _commandGenerator PARAMS((const char*, int));

void initReadline();
int findCommand(Command** out_c, char* name);

/* Warning: modifies str FIXME: add strdup to prevent it? */
int
executeLine(char* str);

void
openShell();

#endif

#include "all.h"

#include <stdio.h>
#include <readline/readline.h>
#include <readline/history.h>
#include "shell.h"

char* _commandGenerator PARAMS((const char*, int));

char**
_completion(text, start, end)
	const char* text;
	int start, end;
{
	return rl_completion_matches(text, _commandGenerator);
}

char*
_commandGenerator(text, state)
	const char* text;
	int state;
{
	static int index, len;
	char* name;
	
	if (state == 0)
	{
		index = 0;
		len = strlen(text);
	}
	
	while ((name = commands[index].name))
	{
		index++;
		if (0 == strncmp(name, text, len))
			return strdup(name);
	}

	return (char*) NULL;
}

int
findCommand(out_c, name)
	Command** out_c;
	char* name;
{
	int i;
	for (i = 0; NULL != commands[i].name; i++)
		if (0 == strcmp(name, commands[i].name))
		{
			*out_c = &commands[i];
			return 1;
		}
	return -1;
}

void
initReadline()
{
	rl_attempted_completion_function = _completion;
	return;
}

/* Warning: modifies str FIXME: add strdup to prevent it? */
int
executeLine(str)
	char* str;
{
	char* commandName;
	char* arg;
	Command* command;
	int ret;
	
	/* Isolate command name and argument from line */
	split(&commandName, &arg, str);
	/* Find function pointer */
	ret = findCommand(&command, commandName);
	if (ret == -1)
	{
		printf("No such command '%s'.\n", commandName);
		ret = 1;
	}
	else
	{
		ret = (*command->func)(arg);
	}
	return ret;
}

void
openShell()
{
	char* rawLine;
	char* line;
	int cont;
	
	initReadline();

	cont = 1;
	while(cont != -1)
	{
		rawLine = readline("> ");
		if (NULL == rawLine)
		{
			printf("quit\n");
			free(rawLine);
			return;
		}
		
		line = trim(rawLine);

		if (0 != strcmp(line, ""))
		{
			add_history(line);
			cont = executeLine(line);
		}

		free(rawLine);
	}
}



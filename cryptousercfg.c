#include "all.h"
#include "globalvars.h"
#include <readline/readline.h>
#include <readline/history.h>
#include "shell.h"
#include "tokencommon.h"
#include "ctabcommon.h"

/* Function declarations from userscfgcommands.c, no need
 * to create separate .h file for only two declaration. */
int cUSourceT(char* arg);
int cUSourceF(char* arg);

int
main(argc, argv)
	int argc;
	char** argv;
{
	int ret;
	ret = getAuthdata(0);
	if (-1 == ret)
	{
		perror("Shared memory error");
		exit(1);
	}

	ctab = xmlParseFile(CONFIG_FILE);
	if (ctab == NULL)
	{
		fprintf(stderr, "Config file parsing error.\n");
		exit(1);
	}
	
	printf("cryptousercfg 1.0\n\n");

	
	/* Check master key encmagic */
	ret = checkMKEncMagic();
	/* Start shell only if encmagic is correct */
	if (-1 != ret)
	{
		/* Initialize cryptokenFile */
		if (argc >= 2)
			cUSourceF(argv[1]);
		else
			cUSourceT(cryptokenFile = NULL);
		
		printf("Type 'help' for help, 'quit' to exit program.\n");
		printf("You can use command completion with TAB key.\n");
		
		openShell();
	}

	if (NULL != cryptokenFile)
		free(cryptokenFile);
	
	shmdt(authdata);
	xmlFreeDoc(ctab);
	
	return 0;
}

#include "all.h"
#include <readline/readline.h>
#include <readline/history.h>
#include "shell.h"
#include "cryptokencfg.h"
#include "tokencommon.h"
#include "globalvars.h"

int
main(argc, argv)
	int argc;
	char** argv;
{
	if (argc < 2)
	{
		fprintf(stderr, "cryptokencfg 1.0\n\n");
		fprintf(stderr, "Usage:\n");
		fprintf(stderr, "\tcryptokencfg token_configuration_file\n");
		exit(1);
	}

	ctokenFile = argv[1];
	
	ctoken = xmlParseFile(ctokenFile);
	if (ctoken == NULL)
	{
		fprintf(stderr, "Config file parsing error.\n");
		exit(1);
	}
	
	printf("cryptokencfg 1.0\n");
	printf("\nType 'help' for help, 'quit' to exit program.\n");
	printf("You can use command completion with TAB key.\n");
	openShell();
	
	xmlFreeDoc(ctoken);
	
	return 0;
}

#include "all.h"
#include "globalvars.h"

void usage()
{
	fprintf(stderr, "masterkeycfg 1.0\n\n");
	fprintf(stderr, "usage:\n");
	fprintf(stderr, "\tmasterkeycfg command\n\n");
	fprintf(stderr, "where command may be:\n");
	fprintf(stderr, "\tcreate - generate random masterkey and place "
									"it in shared memory\n");
	fprintf(stderr, "\tclean  - clean master key from shared memory\n");
	fprintf(stderr, "\tshow   - if master key is in shared memory - "
									"display it in hex\n");
	fprintf(stderr, "\tset mk - set masterkey from mk hex string\n\n");

	fprintf(stderr, "Warning! Remember to turn off shell history when using 'set' command.\n");
	fprintf(stderr, "Otherwise, masterkey will be saved in history file!\n");
	fprintf(stderr, "In bash you can achieve that by issuing:\n");
	fprintf(stderr, "\texport HISTSIZE=0\n");
	return;
}

/* FIXME: maybe create CLI as in crypto*cfg, to prevent security
 *        problems with 'set' command. */
int
main(argc, argv)
	int argc;
	char** argv;
{
	int i, ret, shm;
	char* command;
	char* mkText;
	u_int8_t* mk;

	if (argc < 2)
	{
		usage();
		exit(1);
	}
	command = argv[1];
	
	if (0 == strcmp(command, "show"))
	{
		ret = getAuthdata(0);
		if (ret == -1)
		{
			perror("Shared memory error");
			exit(1);
		}

		printf("masterkey:");
		for (i = 0; i < 128/8; i++)
		{
			if (i == 128/8/2)
				printf(" ");
			printf(" %.2x", authdata[i]);
		}
		printf("\n");
		
		shmdt(authdata);
		if (ret == -1)
		{
			perror("shmdt");
			exit(1);
		}
	}
	else if (0 == strcmp(command, "clean"))
	{
		shm = getAuthdata(0);
		if (shm == -1)
		{
			perror("Shared memory error");
			exit(1);
		}
	
		/* clean sensitive data */
		memset((void*) authdata, 0, 128/8);

		ret = shmdt(authdata);
		if (ret == -1)
		{
			perror("shmdt");
			exit(1);
		}

		ret = shmctl(shm, IPC_RMID, NULL);
		if (ret == -1)
		{
			perror("shmctl");
			exit(1);
		}
	}
	else if (0 == strcmp(command, "create"))
	{
		ret = getAuthdata(1);
		if (ret == -1)
		{
			perror("Shared memory error");
			exit(1);
		}

		/* Generate 128 bits of random data */
		ret = RAND_bytes(authdata, 128/8);
		if (ret == 0)
		{
			fprintf(stderr, "Rand_bytes: %lu\n", ERR_get_error());
			shmdt(authdata);
			if (ret == -1)
			{
				perror("shmdt");
				exit(1);
			}
			ret = shmctl(shm, IPC_RMID, NULL);
			if (ret == -1)
			{
				perror("shmctl");
				exit(1);
			}
			exit(1);
		}

		shmdt(authdata);
		if (ret == -1)
		{
			perror("shmdt");
			exit(1);
		}
	}
	else if (0 == strcmp(command, "set"))
	{
		if (argc < 3)
		{
			fprintf(stderr,
							"Command 'set' requires hex string as argument.\n");
			exit(1);
		}
		mkText = strdup(argv[2]);
		
		cleanWhiteSpace(&mkText);

		if (128/8*2 < strlen(mkText))
		{
			fprintf(stderr, "Key too long.\n");
			free(mkText);
			exit(1);
		}
		else if (128/8*2 > strlen(mkText))
		{
			fprintf(stderr, "Key too short.\n");
			free(mkText);
			exit(1);
		}
		
		ret = hex2byte(&mk, mkText, 128/8);
		free(mkText);
		if (ret == -1)
		{
			fprintf(stderr, "Key contains illegal characters.\n");
			exit(1);
		}
		
		/* The key is good - we can copy it to shared memory */
		ret = getAuthdata(1);
		if (ret == -1)
		{
			perror("Shared memory error");
			exit(1);
		}

		memcpy(authdata, mk, 128/8);

		shmdt(authdata);
		if (ret == -1)
		{
			perror("shmdt");
			exit(1);
		}
	}
	else
	{
		usage();
		fprintf(stderr, "\nUnrecognized command: %s\n", command);
		exit(1);
	}
	
	return 0;
}

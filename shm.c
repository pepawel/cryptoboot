#include "all.h"
#include "globalvars.h"

int
getAuthdata(create)
	int create;
{
	int flags;
	int shm;
	key_t shmKey;
	u_int8_t* ptr;
	
	flags = create ? IPC_CREAT|IPC_EXCL : 0;
	
	shmKey = ftok("/", 0xcb);
	if (shmKey == -1) return -1;
	
	shm = shmget(shmKey, 128/8, flags|0600);
	if (shm == -1) return -1;

	ptr = (u_int8_t*) shmat(shm, NULL, 0);
	if ((int)ptr == -1) return -1;

	authdata = ptr;
	return shm;
}


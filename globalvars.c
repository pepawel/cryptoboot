#include "all.h"
#include "globalvars.h"

/* Global variables: configuration document pointers */
xmlDocPtr ctoken;
xmlDocPtr ctab;
/* authdata: byte array holding masterkey */
u_int8_t* authdata;

/* Only used by cryptousercfg:
 * Flag indicating where cryptoken.xml can be found
 * NULL - on token
 * any other value - in specified file
 */
char* cryptokenFile;

#include "all.h"

/* Global variables: configuration document pointers */
extern xmlDocPtr ctoken;
extern xmlDocPtr ctab;
/* authdata: byte array holding masterkey */
extern u_int8_t* authdata;

/* Only used by cryptousercfg:
 * Flag indicating where cryptoken.xml can be found
 * NULL - on token
 * any other value - in specified file
 */
extern char* cryptokenFile;

#include "all.h"
#include "util.h"
#include "tokencommon.h"
#include "globalvars.h"

/* These GUI variables are used in almost every function
 * - so they are global for convenience
 */
CDKSCREEN *cdkscreen = (CDKSCREEN*) NULL;
WINDOW *cursesWin = (WINDOW*) NULL;
CDKLABEL *helpLabel = (CDKLABEL*) NULL;

void
setHelpLabel(str)
	char* str;
{
	setCDKLabel(helpLabel, &str, 1, FALSE);
}

int
decryptUserTokenKeyWindow(out_userTokenKey, passphrase, userNode)
	u_int8_t** out_userTokenKey;
	char* passphrase;
	xmlNodePtr userNode;
{
	CDKLABEL* label;
	char* msg[3];
	u_int8_t* ukey; /* decrypted userTokenKey */
	int ret;

	msg[0] = "";
	msg[1] = "  Checking passphrase...  ";
	msg[2] = "";
	
	label = newCDKLabel(cdkscreen, CENTER, CENTER, msg, 3,
										 TRUE, FALSE);
	if (label == (CDKLABEL*) NULL) 
	{
		printf("Internal error.\n"); exit(1);
	}
	setCDKLabelBackgroundColor(label, "</5>");
	drawCDKLabel(label, TRUE);
	setHelpLabel("Please wait, it may take some time depending on iteration count.            ");

	ret = getUserTokenKey(&ukey, NULL, userNode, passphrase);
	if (ret != -1)
		*out_userTokenKey = ukey;

	setCDKLabelBackgroundColor(label, "</0>");
	destroyCDKLabel(label);

	return ret;
}

int
okWindow(msg, lineCount)
	char** msg;
	int lineCount;
{
	CDKDIALOG* dialog;
	char* button="OK";
	dialog = newCDKDialog(cdkscreen, CENTER, CENTER, msg, lineCount,
												&button, 1, A_REVERSE, FALSE, TRUE, FALSE);
	if (dialog == (CDKDIALOG*) NULL)
	{
		return -100;
	}
	setCDKDialogBackgroundColor(dialog, "</5>");
	drawCDKDialog(dialog, TRUE);
	activateCDKDialog(dialog, (chtype*) NULL);
	setCDKDialogBackgroundColor(dialog, "</0>");
	destroyCDKDialog(dialog);
	return 1;
}

int
msgWindow(msg, lineCount, timeout)
	char** msg;
	int lineCount;
	int timeout;
{
	CDKLABEL* label;
	label = newCDKLabel(cdkscreen, CENTER, CENTER, msg, lineCount,
										 TRUE, FALSE);
	if (label == (CDKLABEL*) NULL)
	{
		return -100;
	}
	setCDKLabelBackgroundColor(label, "</5>");
	drawCDKLabel(label, TRUE);
	sleep(timeout);
	setCDKLabelBackgroundColor(label, "</0>");
	destroyCDKLabel(label);
	return 1;
}

int
passphraseEntryWindow(out_passphrase, userNode)
	char** out_passphrase;
	xmlNodePtr userNode;
{
	char* titleLeft = "Enter passphrase for user </B>";
	char* titleTmp;
	char* title;
	char* userName;
	CDKMENTRY* entry;
	char* passphrase;
	int ret;

	userName = xmlGetProp(userNode, "name");
	xstrcat(&titleTmp, titleLeft, (char*) userName);
	xmlFree(userName);
	xstrcat(&title, titleTmp, "<!B>: ");
	free(titleTmp);
	
	entry = newCDKMentry(cdkscreen, CENTER, CENTER, title, "",
									  	 A_NORMAL, ' ', vHMIXED,
											 45, 2, 20, 0, TRUE, FALSE);
	if (entry == (CDKMENTRY*) NULL)
	{
		printf("CDK error.\n"); exit(1);
	}
	setHelpLabel("Press ENTER to accept passphrase, press ESC to return to user selection.    ");
	setCDKMentryBackgroundColor(entry, "</5>");
	passphrase = activateCDKMentry(entry, (chtype*) NULL);
	if (entry->exitType == vNORMAL)
	{
		*out_passphrase = strdup(passphrase);
		ret = 1;
	}
	else
		ret = -1;
	setCDKMentryBackgroundColor(entry, "</0>");
	destroyCDKMentry(entry);
	free(title);
	return ret;
}

int
insertTokenWindow(ctoken, timeout)
	xmlDocPtr* ctoken;
	int timeout;
{
	char* text[5];
	char* tokenStateText = "unknown";
	char tsline[80];
	char toline[80];
	CDKLABEL* label;
	int input;
	WINDOW* tmpWin;
	int timeLeft, sec;
	int ret;
	xmlNodePtr cur;
	
	xmlChar* tokenDev;
	xmlChar* tokenFS;
	xmlChar* tokenDir;
	xmlChar* tokenFile;
	
	/* Get token info from config file */
	cur = xmlDocGetRootElement(ctab);
	
	for (cur = cur->xmlChildrenNode; cur != NULL; cur = cur->next)
	{
		if (0 == xmlStrcmp(cur->name, (const char*) "token"))
		{
			tokenDev = xmlGetProp(cur, "dev");
			tokenFS = xmlGetProp(cur, "fstype");
			tokenDir = xmlGetProp(cur, "mnt");
			tokenFile = xmlGetProp(cur, "file");
			break;
		}
	}
	
	sprintf(tsline, "Token state: </B>%s<!B>", tokenStateText);
	
	if (timeout != -1)
	{
		sprintf(toline, "%2d seconds remaining...", timeout);
		setHelpLabel("Press C to cancel timeout, press Q to quit.                                 ");
	}
	else
	{
		sprintf(toline, "Token detection in progress...");
		setHelpLabel("Press Q to quit.                                                            ");
	}
	text[0] = "Please insert security token.          ";
	text[1] = "";
	text[2] = tsline;
	text[3] = "";
	text[4] = toline;
	
	label = newCDKLabel(cdkscreen, CENTER, CENTER, text, 5,
									  	TRUE, FALSE);
	if (label == (CDKLABEL *)NULL)
	{
		printf("CDK error.\n");
		exit(1);
	}
	setCDKLabelBackgroundColor(label, "</5>");
	drawCDKLabel(label, TRUE);
	
	/* Need to create invisible window, to do wgetch;
	 * New window creation is needed, because wgetch erases cdk window
	 * otherwise. */
	tmpWin = newwin(1,1,0,0);
	curs_set(0); /* hide cursor */
	nodelay(tmpWin, TRUE);
	timeLeft = timeout;
	sec = 10;
	while(1)
	{
		input = wgetch(tmpWin);
		if ((input == 'q') || (input == 'Q')) break;
		if ((input == 'c') || (input == 'C'))
		{
			timeout = -1;
			sprintf(toline, "Token detection in progress...");
			setHelpLabel("Press Q to quit.                                                            ");
		}
		
		usleep(100000);
		
		if (sec == 0)
		{
			if (timeout != -1)
			{
				timeLeft--;
			}
			sec = 10;
		}
		sec--;

		if (timeLeft == 0) break;

		if ((sec == 0) || (sec == 5))
		{
			ret = getTokenConfig(tokenDev, tokenFS,
													 tokenDir, tokenFile, &tokenStateText);
			
			/* Update display */
			sprintf(tsline, "Token state: </B>%s<!B>", tokenStateText); 
			if (-1 != timeout)
				sprintf(toline, "%2d seconds remaining...", timeLeft);
			else
				sprintf(toline, "Token detection in progress...");
			setCDKLabelMessage(label, text, 5);
			
			if (-1 == ret)
			{
				sleep(3);
				exit(1);
			}
			else if (1 == ret)
			{
				sleep(1);
				break;
			}
		}
	}
	
	nodelay(tmpWin, FALSE);
	delwin(tmpWin);
	curs_set(1); /* show cursor */
	
	setCDKLabelBackgroundColor(label, "</0>");
	destroyCDKLabel(label);

	/* Free memory used by xml strings */
	xmlFree(tokenDev);
	xmlFree(tokenFS);
	xmlFree(tokenDir);
	xmlFree(tokenFile);

	return ret;
}

void
createUserTab(out_userTab, nodeTab, userCount, size)
	char*** out_userTab;
	xmlNodePtr* nodeTab;
	int userCount;
	int size;
{
	char** tab;
	int i, len, marg;
	char* line;
	char* name;
	
	tab = malloc(sizeof(char*) * userCount);
	for (i = 0; i < userCount; i++)
	{
		name = (char*) xmlGetProp(nodeTab[i], "name");
		tab[i] = name;
	}
	for (i = 0; i < userCount; i++)
	{
		name = tab[i];
		line = malloc(sizeof(char) * (size + 1));
		len = strlen(name);
		if (len > size)
			len = size;
		/* Fill string with spaces */
		memset(line, ' ', size);
		line[size] = '\0';
		marg = (size - len) / 2;
		memcpy(line + marg, name, len);
		free(name);
		tab[i] = line;
	}
	
	*out_userTab = tab;
	return;
}

/* FIXME: check if there is at least one user defined in cryptotab
 *        at begining of readtoken - if not bail out with error */
int
userSelectWindow(out_tUserNode, out_dUserNode, out_oneUserFlag)
	xmlNodePtr* out_tUserNode;
	xmlNodePtr* out_dUserNode;
	int* out_oneUserFlag;
{
	/* Declare variables. */
	CDKSCROLL *scrollList	= (CDKSCROLL *)NULL;
	char* title			= "Select your username";
	char** userTab;
	char* msg[3];
	int selection, userCount, ret, i;
	xmlNodePtr* dUNodeTab;
	xmlNodePtr* tUNodeTab;
	xmlNodePtr* diskTab;
	xmlNodePtr* tokenTab;
	
	fillUserTab(&tokenTab, ctoken);
	fillUserTab(&diskTab, ctab);
	userCount = joinUNodeTabs(&tUNodeTab, &dUNodeTab, tokenTab, diskTab);
	if (0 == userCount)
	{
		for (i = 0; NULL != tokenTab[i]; i++);
		if (0 == i)
		{
			msg[0] = "No users on token found.";
			okWindow(msg, 1);
			ret = -1;
		}
		else
		{
			msg[0] = "No user on token is allowed";
			msg[1] = "to access this machine.";
			okWindow(msg, 2);
			ret = -1;
		}
	}
	else if (1 == userCount)
	{
		/* Only one user - we can skip user selection */
		*out_tUserNode = tUNodeTab[0];
		*out_dUserNode = dUNodeTab[0];
		*out_oneUserFlag = 1;
		ret = 1;
	}
	else
	{
		/* Create string array for CDK scrollList */
		createUserTab(&userTab, tUNodeTab, userCount, strlen(title));
	
		/* Create the scrolling list. */
		scrollList = newCDKScroll (cdkscreen, CENTER, CENTER, NONE,
								 userCount + 3, 1, title, userTab, userCount,
								 FALSE, A_REVERSE, TRUE, FALSE);

		if (scrollList == (CDKSCROLL *)NULL)
		{
			printf("CDK errror.\n");
			exit(1);
		}
			
		setCDKScrollBackgroundColor(scrollList, "</5>");
		drawCDKScroll (scrollList, 1);
		
		setHelpLabel("Select user with arrows, then press ENTER. Press ESC to go back.             "); 
		
		/* Activate the scrolling list. */
		selection = activateCDKScroll (scrollList, (chtype *)NULL);
		setCDKScrollBackgroundColor(scrollList, "</0>");
	
		if (scrollList->exitType == vNORMAL)
		{
			*out_tUserNode = tUNodeTab[selection];
			*out_dUserNode = dUNodeTab[selection];
			ret = 1;
		}
		else
			ret = -1;
		/* Free memory used by userTab */
		for (i = 0; i < userCount; i++)
			free(userTab[i]);
		free(userTab);

		destroyCDKScroll (scrollList);
	}
	/* Free xml node arrays */
	free(tokenTab);
	free(diskTab);
	free(tUNodeTab);
	free(dUNodeTab);

	return ret;
}


int
main()
{
	char* dummyHelp = "                                                                            ";
	char* cryptoBootTitle = {"                 </B>Cryptoboot/readToken 1.0</!B> by Pawel Pokrywka                 "};
	char* msg[10]; /* for ok messages */
	CDKLABEL* titleLabel = (CDKLABEL *)NULL;
	int i, ret;
	xmlNodePtr tUserNode;
	xmlNodePtr dUserNode;
	char* passphrase;
	u_int8_t* userTokenKey;
	u_int8_t* masterKey;
	int loopTokenInsertionPhase;
	int loopUserSelectionPhase;
	int insertTokenTimeout = 5;
	int ouflag;
	int successFlag;
	int shm;
	
	/* Load configuration */
	ctab = xmlParseFile(CONFIG_FILE);
	if (ctab == NULL)
	{
		fprintf(stderr, "Config file parsing error.\n");
		exit(1);
	}
								
	/* Get shared memory segment for masterKey */
	shm = getAuthdata(1);
	if (shm == -1)
	{
		perror("Shared memory error");
		exit(1);
	}

	/* Set up ncurses */ 
	cursesWin = initscr();
	/* Set up CDK */
	cdkscreen = initCDKScreen (cursesWin);
	/* Set up CDK Colors. */
	initCDKColor();

	/* NCurses variable - time after single ESC works
	 * - by default it is 1000 = 1s
	 */
	ESCDELAY = 50;
	
	/* Title window */
	titleLabel = newCDKLabel(cdkscreen, LEFT, TOP, &cryptoBootTitle, 1,
									  			 FALSE, FALSE);
	setCDKLabelBackgroundColor(titleLabel, "</5>");

	/* Help window */
	helpLabel = newCDKLabel(cdkscreen, LEFT, BOTTOM, &dummyHelp, 1,
													FALSE, FALSE);
	setCDKLabelBackgroundColor(helpLabel, "</5>");

	drawCDKLabel(titleLabel, FALSE);
	drawCDKLabel(helpLabel, FALSE);

	successFlag = 0;
	do
	{
		/* Prompt for the token initially only one time */
		loopTokenInsertionPhase = 0;
		ret = insertTokenWindow(&ctoken, insertTokenTimeout);
		if (ret == 1)
		{
			do
			{
				/* Prompt for username initially only one time */
				loopUserSelectionPhase = 0;
				ouflag = 0;
				ret = userSelectWindow(&tUserNode, &dUserNode, &ouflag);
				if (ret == 1)
				{
					/* Get passphrase */
					ret = passphraseEntryWindow(&passphrase, tUserNode);
					if (ret == 1)
					{
						/* Derive userTokenKey */
						ret = decryptUserTokenKeyWindow(&userTokenKey, passphrase,
																						tUserNode);
						free(passphrase); /* passphrase is not needed now */
						if (ret == 1)
						{
							/* Decrypt masterKey using userTokenKey */
							ret = decryptMasterKey(&masterKey, userTokenKey,
																		 dUserNode);
							free(userTokenKey); /* user key not needed now */
							if (ret == 1)
							{
								/* Copy masterKey to shared memory segment */
								for (i = 0; i < 128/8; i++)
									authdata[i] = masterKey[i];
									
								/* Free masterKey memory */
								free(masterKey);
									
								msg[0]="";
								msg[1]="  Login successfull.  ";
								msg[2]="";
								setHelpLabel("Decrypted Master Key placed in shared memory.");
								msgWindow(msg, 3, 2);
								successFlag = 1;
							}
							else
							{
								msg[0]="Master key decryption failure.";
								okWindow(msg, 1);
								loopUserSelectionPhase = 1;
							}
						}
						else
						{
							msg[0]="Incorrect passphrase.";
							okWindow(msg, 1);
							loopUserSelectionPhase = 1;
						}
					}
					else if (ouflag == 1)
					{
						/* User wants to get back to token insertion phase */
						loopTokenInsertionPhase = 1;
						insertTokenTimeout = -1;
					}
					else
					{
						/* User wants to get back to user selection */
						loopUserSelectionPhase = 1;
					}
				}
				else
				{
					/* User wants to get back to token insertion */
					loopTokenInsertionPhase = 1;
					insertTokenTimeout = -1;
				}
			}
			while(loopUserSelectionPhase == 1);
			/* Free token xml file */
			xmlFreeDoc(ctoken);	
		}
	}
	while(loopTokenInsertionPhase == 1);
	/* Free config file */
	xmlFreeDoc(ctab);
	
	/* Clean up cdk */
	destroyCDKLabel(titleLabel);
	destroyCDKLabel(helpLabel);
	destroyCDKScreen(cdkscreen);
	delwin (cursesWin);
	endCDK();

	if (1 != successFlag)
	{
		/* Destroy shm segment */
		ret = shmdt(authdata);
		if (ret == -1)
		{
			perror("shmdt");
			exit(2);
		}

		ret = shmctl(shm, IPC_RMID, NULL);
		if (ret == -1)
		{
			perror("shmctl");
			exit(3);
		}
		return 1;
	}
	else
		return 0;
}

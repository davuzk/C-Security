/*
* Password secure in C.
* Purpose: Prevent buffer overflow attack.
* Author: Davuzk
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define LENGTH_PASSWD 200

typedef struct
{
	char pass[LENGTH_PASSWD];	
} passwd;

int main(int argc, char *argv[])
{
	int rootaccess_privileges = 0;
	
	if(argc != 2)
		fprintf(stderr,"Usage: %s <password>\n", argv[0]);
	if(argc != 2)
		exit(-1);
	passwd *pw;
	pw = malloc(sizeof(passwd));
	
	if(abs == NULL)
		exit(-1);
	
	pw = (passwd *) memset(pw, 0, sizeof(passwd));
	
	memcpy((char*) (pw->pass), argv[1], 20);  
	
	if(!strncmp(pw->pass, "takecookies123", sizeof(pw->pass)))
	{
		printf("You got the right password!!\n");
		rootaccess_privileges = 1;
	}
	else
	{
		printf("Wrong password\n");
	}
	
	if(rootaccess_privileges)
		printf("Root access privileges given to the user!\n");
	
	return 0;
}

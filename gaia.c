/*
# Name: Gaia (Gateway Anaöycis Interface Application).
# Program type: Port scanner.
# Author: Davuzk aka Dauxna/Thedabosk189
# Date: 2015-09-27.
*/

#include <netinet/in.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#define NETWORK_ERROR -1

/* dlstn port scanner aka gaia*/
int main(int argc, char** argv)
{
    signed int socket_initializer, startingport, endingport, finalport, timerange;
    struct sockaddr_in addr;
	
	if(argc < 4)
	{
		fprintf(stderr,"[ GAIA (Gateway Analycis Interface Application) Port Scanner | Davuzk ]\n"\
		"Usage: %s <host> <start port> <end port>\n", argv[0]);
		exit(0);
	}

    if((socket_initializer = socket(AF_INET, SOCK_STREAM, 0)) == -NETWORK_ERROR)
    {
        printf("Could not create socket!\n");
        exit(1);
    }
	startingport = atoi(argv[2]),endingport = atoi(argv[3]);
	
    printf("\n[*] Starting scan at: %s port: %d end port: %d\n\n", argv[1], startingport, endingport);
    
	for(finalport = startingport; finalport <= endingport; finalport++)
	{
		for(startingport = startingport; startingport<=endingport; startingport++)
		{
			addr.sin_addr.s_addr = inet_addr(argv[1]);
   			addr.sin_family = AF_INET;
    		addr.sin_port = htons(startingport);
			
			if(connect(socket_initializer,( struct sockaddr*)&addr, sizeof(addr)) < 0)
    		{
       			printf("[-] Port: %d/%d is closed at host: %s\n\n", startingport, endingport, argv[1]);
    		}
    		else
    		{
        		printf("[+] Port: %d/%d is open at host: %s\n\n", startingport, endingport, argv[1]);
    		}
		}
    	
	}
	
	close(socket_initializer);
   
}

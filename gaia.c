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

struct cvsparser
{
	const char *targethost_scan;
	signed int socket_initializer;
	signed int startingport;
	signed int endingport;
	signed int finalport;
	signed int timerange;
};

/*--------------------------------------------------------------------*/

void gaia_usage(const char *prog)
{
	fprintf(stderr,"Usage: %s -host <host> -port <start port> <end port>\n", prog);
	exit(-1);
}

/*--------------------------------------------------------------------*/

int main(int argc, char** argv)
{
	if(argc < 4)
		gaia_usage(argv[0]);
		
    struct cvsparser args;
    
    struct sockaddr_in addr;
	
    if((args.socket_initializer = socket(AF_INET, SOCK_STREAM, 0)) == NETWORK_ERROR)
    {
        printf("Could not create socket!\n");
        exit(-1);
    }
	args.startingport = atoi(argv[2]), args.endingport = atoi(argv[3]);
	
    printf("\n[*] Starting scan at: %s port: %d end port: %d\n\n", argv[1], args.startingport, args.endingport);
    
	for(args.finalport = args.startingport; args.finalport <= args.endingport; args.finalport++)
	{
		for(args.startingport = args.startingport; args.startingport<=args.endingport; args.startingport++)
		{

			addr.sin_addr.s_addr = inet_addr(argv[1]);
   			addr.sin_family = AF_INET;
    		        addr.sin_port = htons(args.startingport);
			
			if(connect(args.socket_initializer,( struct sockaddr*)&addr, sizeof(addr)) < 0)
       			    printf("[-] Port: %d/%d is closed at host: %s\n\n", args.startingport, args.endingport, argv[1]);
    		        else
        		    printf("[+] Port: %d/%d is open at host: %s\n\n", args.startingport, args.endingport, argv[1]);
    		
		}
    	
	
	}
	close(args.socket_initializer);
   
}

/*--------------------------------------------------------------------*/

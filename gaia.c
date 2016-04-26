/*
# Name: Gaia (Gateway Ana�ycis Interface Application).
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

typedef struct
{
	const char *targethost_scan;
	signed int starting_port;
	signed int ending_port;
	signed int final_port;
} conection;

void program_usage(char *msg)
{
	fprintf(stderr,"Usage: %s -host <host> -port <start port> <end port>", msg);
	exit(0);
}

int main(int argc, char* argv[])
{
   	
    struct sockaddr_in addr;
	
    signed int sock_connectioncheck;
	
    if(argc != 6)
	program_usage(argv[0]);
    
    conection *conc;
	conc = malloc(sizeof(conection));

    if((sock_connectioncheck = socket(AF_INET, SOCK_STREAM, 0)) == -NETWORK_ERROR)
        exit(1);
    
    
    conc->targethost_scan = argv[2];
    
	conc->starting_port = atoi(argv[4]), conc->ending_port = atoi(argv[5]);
	if(strncmp(argv[1], "-host", 5) == 0 || (strncmp(argv[3],"-port", 5) == 0))
	{
	
	printf("\n[+] Starting scan at: %s port: %d end port: %d\n\n", argv[2], conc->starting_port, conc->ending_port);
    
	for(conc->final_port = conc->starting_port; conc->final_port <= conc->ending_port; ++conc->final_port)
		for(conc->starting_port = conc->starting_port; conc->starting_port<=conc->ending_port; ++conc->starting_port)
		{
			addr.sin_addr.s_addr = inet_addr(conc->targethost_scan);
   			addr.sin_family = AF_INET;
	    		addr.sin_port = htons(conc->starting_port);
			
			if(connect(sock_connectioncheck,( struct sockaddr*)&addr, sizeof(addr)) < 0)
       		            printf("[-] Port: %d/%d is closed at host: %s\n\n", conc->starting_port, conc->ending_port, conc->targethost_scan);
    			else
        		    printf("[+] Port: %d/%d is open at host: %s\n\n", conc->starting_port, conc->ending_port, conc->targethost_scan);
    		
		}
    	
	
	}
	close(sock_connectioncheck);

}

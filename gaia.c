/* Libraries needed */
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
 
#define TXBUFFSIZE 512
 
typedef struct
{
     
const uint8_t *targethost_scan;
const uint8_t *end_targethost_scan;
const uint8_t *destination_textfile;
const uint8_t *desthost_oneport;
const uint8_t *threehosts_desthost_first;
const uint8_t *threehosts_desthost_second;
const uint8_t *threehosts_desthost_third;
const uint8_t *frth_firsthost;
const uint8_t *frth_sechost;
const uint8_t *frth_thrdhost;
const uint8_t *frth_frthhost;
const uint8_t *fif_firstost;
const uint8_t *fif_secost;
const uint8_t *fif_thirdost;
const uint8_t *fif_fourost;
const uint8_t *fif_fifost;
const uint8_t *ftpcheckhost;
const uint8_t *sshcheckhost;
const uint8_t *smtpcheckhost;
const uint8_t *httpcheckhost;
const uint8_t *httpscheckhost;
const uint8_t *threeportshost;
int32_t ownnet_sock_check;
int32_t sock_connectioncheck;
int32_t multi_sock_connection;
int32_t text_sock_connection;
int32_t one_port_sockcheck;
int32_t third_host_check;
int32_t frth_host_check;
int32_t fif_host_check;
int32_t ftp_concheck;
int32_t ssh_concheck;
int32_t smtp_conchecck;
int32_t http_concheck;
int32_t https_concheck;
int32_t threeport_hchck;
int32_t fourport_hcheck;
uint32_t *targeted_startport;
uint32_t *targeted_endport;
uint32_t *startport_destscan;
uint32_t *multi_scan_termbool;
uint32_t *text_scan_termbool;
uint32_t *endport_destscan;
uint32_t *multi_start_port;
uint32_t *multi_end_port;
uint32_t *text_startport;
uint32_t *text_endport;
uint32_t *ptprincipal_zerovalue;
uint32_t threeport_first;
uint32_t threeport_sec;
uint32_t threeport_thrd;
uint32_t principal_zerovalue;
uint32_t multi_term_value;
uint32_t oneport_startport;
uint32_t text_term_value;
uint32_t starting_port;
uint32_t ending_port;
uint32_t final_port;
uint32_t thrdprt;
uint32_t frthprt;
uint32_t fifprt;
uint32_t frthone;
     
} conection;
 
typedef struct
{
    const uint8_t *tgt_desthost_primal;
    const uint8_t *tgt_desthost_final;
    int32_t one_tgt_sockcheck;
    uint32_t *tgt_dest_port;
    uint32_t nonpt_tgt_dest_port;
        const uint8_t * frthpf;
        uint32_t frthpsc;
        uint32_t frthptd;
        uint32_t frthpft;
        uint32_t frthpfv;
     
} second;
 
struct MultiPortsBools{
    uint32_t *scandone;
    uint32_t scandonev;
    uint32_t onlistenfs;
    uint32_t onlistensc;
    uint32_t onlistentd;
    uint32_t onlistenft;
    uint32_t checkonline;
    int32_t globnerr; // global network error
};
 
struct MultiHostsBool{
    uint32_t *terminated;
    uint32_t terminatedv;
    uint32_t onfirst;
    uint32_t onsec;
    uint32_t ontd;
    uint32_t onft;
};
 
/* instructions of the program usage */
static int
program_usage(uint8_t *eMsg)
{
    fprintf(stderr, "\nInstructions of the program usage are the following:\n");
    fprintf(stderr,"\n[ Standard usage ]\n\nUsage: %s [target_host] [start port] [end port] - single host scan\n", eMsg);
    fprintf(stderr,"\nUsage: %s [start host_range] [end host_range] [start port] [end port] - multiple hosts scan\n", eMsg);
    fprintf(stderr,"\n[ Exclusive usage ]\n");
    fprintf(stderr, "\nUsage: %s -lh [start port] [end port] - to scan the localhost\n", eMsg);
    fprintf(stderr,"\nUsage: %s -<hosts> (max 5) [destination hosts] [destination port] - hosts port scan\n", eMsg);
    fprintf(stderr, "\nUsage: %s -port=1 [destination host] [destination port]\n", eMsg);
    fprintf(stderr,"\n[ Protocol  scan usage ]\n\nUsage: %s -cftp [destination host] [destination port] - check if server runs FTP\n", eMsg);
    fprintf(stderr,"\nUsage: %s -cssh [destination host] [destination port] - check if server runs SSH\n", eMsg);
     
    exit(EXIT_FAILURE);
    return 1;
}
 
/* output message for a multiple scan process */
static uint8_t *alert_multiscan_process(const uint8_t *mutli_scan_msg, const uint8_t *multi_targ_scm,
const uint8_t *multi_dest_host, uint32_t multi_dest_startport, uint32_t multi_dest_endport)
{   
    printf(mutli_scan_msg, multi_targ_scm, multi_dest_host, multi_dest_startport, multi_dest_endport);
     
}
 
// outputs a error message if there's any network error. (This function isn't static so it can be re-called by another function)
int netsock_initializationfail(uint8_t *socketfailure_message)
{
    perror(socketfailure_message);
    exit(EXIT_FAILURE);
}
 
/* scan two IP addresses */
static uint8_t* perform_targeted_scan(const uint8_t *sHost_range, const uint8_t *eHost_range,
                                            uint32_t sPort, uint32_t ePort)
{
     // t for targeted access to the structure function
    conection *tCon;
    /* targeted struct call */
    tCon = malloc(sizeof(conection));
    /* free the memory of tCon */
    uint32_t oe; /* to output the error message of the socket */
     
    struct sockaddr_in sAddr; /* for the single address */
    struct sockaddr_in mAddr; /* for the multiple address */
     
    tCon->targethost_scan = sHost_range;
    tCon->end_targethost_scan = eHost_range;
    tCon->starting_port = sPort;
    tCon->ending_port = ePort;
     
    tCon->multi_term_value = 0;
    tCon->multi_scan_termbool = &tCon->multi_term_value;
     
    tCon->multi_start_port = &tCon->starting_port;
    tCon->multi_end_port = &tCon->ending_port;
     
    if((tCon->multi_sock_connection = socket(AF_INET, SOCK_STREAM, 0)) == -1)
        {
        oe = netsock_initializationfail("Unable to connect"); // could not create a socket
    }
     
    alert_multiscan_process("\nScanning from host range: %s - %s:%d/%d\n\n", 
    tCon->targethost_scan, tCon->end_targethost_scan, *tCon->multi_start_port,
                                                        *tCon->multi_end_port);
     
    while(!*tCon->multi_scan_termbool){
     
        for(tCon->final_port = tCon->starting_port; tCon->final_port <= tCon->ending_port; tCon->final_port++){
             
            for(tCon->starting_port = tCon->starting_port; 
                tCon->starting_port<=tCon->ending_port; 
                tCon->starting_port++)
                {
                 
                sAddr.sin_addr.s_addr = inet_addr(tCon->targethost_scan);
            sAddr.sin_family = AF_INET;
            sAddr.sin_port = htons(tCon->starting_port);
                 
            mAddr.sin_addr.s_addr = inet_addr(tCon->end_targethost_scan);
            mAddr.sin_family = AF_INET;
            mAddr.sin_port = htons(tCon->starting_port);
                 
            if(connect(tCon->multi_sock_connection,( struct sockaddr*)&sAddr,
                        sizeof(sAddr)) < 0)
                            printf("\n\t%s:%d/%d closed\n", tCon->targethost_scan, tCon->starting_port, tCon->ending_port);        
            else
                            printf("\n\t%s:%d/%d open\n", tCon->targethost_scan, tCon->starting_port, tCon->ending_port);
                 
                 
            if(connect(tCon->multi_sock_connection,( struct sockaddr*)&mAddr,
                        sizeof(mAddr)) < 0)
                printf("\n\t%s:%d/%d closed\n",tCon->end_targethost_scan, tCon->starting_port, tCon->ending_port);
            else
                printf("\n\t%s:%d/%d open\n", tCon->end_targethost_scan, tCon->starting_port, tCon->ending_port);
             
        }
             
            tCon->multi_term_value++;
        }
    }
     
    tCon->multi_term_value = 1;
             
    if(*tCon->multi_scan_termbool)
        printf("\nScan finished successfully\n");
     
    close(tCon->multi_sock_connection);
    free(tCon);
    exit(EXIT_SUCCESS);
        return 0;
}
 
/* output message for a single scan process */
static uint8_t *alert_signlescan(const uint8_t *scan_message, const uint8_t *sdest_host, 
                      uint32_t sdest_startport, uint32_t sdest_endport)
{
    printf(scan_message, sdest_host, sdest_startport, sdest_endport);
}
 
//scan your own network (127.0.0.1)
static uint8_t 
scanownnetwork_localghost(uint32_t local_start_port, 
                                uint32_t local_end_port) 
{
     
    //struct sockaddr_in local_addr;
    struct sockaddr_in *local_addrpt;
    local_addrpt = (struct sockaddr_in*)malloc(sizeof(*local_addrpt));
 
    uint32_t ownnet_sockerrmsg;
    conection *local_nw;
    local_nw = malloc(sizeof(conection));
     
    uint32_t *finished_localscan, finished_bool = 0;
     
    finished_localscan = &finished_bool;
     
    local_nw->starting_port = local_start_port;
    local_nw->ending_port = local_end_port;
     
    if((local_nw->ownnet_sock_check = socket(AF_INET, SOCK_STREAM, 0)) == -1){
        ownnet_sockerrmsg = netsock_initializationfail("Unable to connect");
    }
     
    printf("\nScanning the localhost (127.0.0.1) : %d/%d\n", local_start_port,
                                                                    local_end_port);
     
    for(local_nw->final_port = local_nw->starting_port;
        local_nw->final_port <= local_nw->ending_port; local_nw->final_port++){
          for(local_nw->starting_port = local_nw->starting_port; 
              local_nw->starting_port<=local_nw->ending_port;
              local_nw->starting_port++) {
             
            local_addrpt->sin_addr.s_addr = inet_addr("127.0.0.1");
            local_addrpt->sin_family = AF_INET;
            local_addrpt->sin_port = htons(local_nw->starting_port);
             
        if(connect(local_nw->ownnet_sock_check,( struct sockaddr*)local_addrpt,
                sizeof(*local_addrpt)) < 0)
                printf("\t\n127.0.0.1:%d/%d closed\n", local_nw->starting_port, local_nw->ending_port);
            else
                    printf("\t\n127.0.0.1:%d/%d open\n", local_nw->starting_port, local_nw->ending_port);
         
        finished_bool = 1;
        // ^ bolean value if the scan is successfull
        }
    }
     
    if(*finished_localscan)
        printf("\nFinished local scan successfully\n");
         
        return 0;
}
 
// to scan only one single port
static uint8_t*
oneopenport_hostheck(const uint8_t *one_dest_host, uint32_t *one_port)
{
    conection *owo;
    // free memory
    owo = malloc(sizeof(conection));
    static uint32_t oneport_connecterr;
    static uint32_t *onehost_finished, onehost_bvalue = 0;
     
    onehost_finished = &onehost_bvalue;
     
    struct sockaddr_in onp_addr;
        struct sockaddr_in *onp_addrpt;
        onp_addrpt = &onp_addr;
        onp_addrpt = (struct sockaddr_in*)malloc(sizeof(*onp_addrpt));
     
    if((owo->one_port_sockcheck = socket(AF_INET, SOCK_STREAM, 0)) == -1){
        oneport_connecterr = netsock_initializationfail("Unable to connect");
    }
     
    printf("\nScanning: %s:%u\n", one_dest_host, *one_port);
     
    onp_addrpt->sin_addr.s_addr = inet_addr(one_dest_host);
    onp_addrpt->sin_family = AF_INET;
    onp_addrpt->sin_port = htons(*one_port);
     
    if(connect(owo->one_port_sockcheck, (struct sockaddr*)onp_addrpt,
        sizeof(*onp_addrpt)) < 0)
        printf("\n\t%s:%u closed\n", one_dest_host, *one_port);
    else
        printf("\n\t%s:%u open\n", one_dest_host, *one_port);
     
    onehost_bvalue = 1;
     
    if(*onehost_finished)
        printf("\nScan finished successfully!\n");
     
    close(owo->one_port_sockcheck);
    exit(EXIT_SUCCESS);
         
        return 0;
         
}
 
// to scan one port on two hosts
static uint32_t 
oneport_tartetedhostcheck(struct MultiHostsBool mlb, const uint8_t *tgprimal_host, 
                             const uint8_t *tgfinal_host, uint32_t *tgone_port)
{
    second *tgsec;
     
    uint32_t *successfull_baby, condition_tgtfinished = 0;
    // free memory with malloc for tgsec
    tgsec = malloc(sizeof(second));
    struct sockaddr_in tgtone_addr;
    struct sockaddr_in tgtwo_addr;
        struct sockaddr_in *tgtone_addrpt;
        struct sockaddr_in *tgtwo_addrpt;
        tgtone_addrpt = &tgtone_addr;
        tgtwo_addrpt = &tgtwo_addr;
         
    tgtone_addrpt = (struct sockaddr_in*)malloc(sizeof(*tgtone_addrpt));
        tgtwo_addrpt  = (struct sockaddr_in*)malloc(sizeof(*tgtwo_addrpt));
         
        struct MultiHostsBool *mlbp;
        mlbp = &mlb;
    /* call the the error socket */
    uint32_t tgtone_errcall;
    successfull_baby = &condition_tgtfinished;
     
    if((tgsec->one_tgt_sockcheck = socket(AF_INET, SOCK_STREAM, 0)) == -1){
        tgtone_errcall = netsock_initializationfail("Unable to connect");
    }
     
    printf("\nScanning primal host: %s/%s:%u\n", tgprimal_host, 
                                            tgfinal_host, *tgone_port);
 
    tgtone_addrpt->sin_addr.s_addr = inet_addr(tgprimal_host);
    tgtone_addrpt->sin_family = AF_INET;
    tgtone_addrpt->sin_port = htons(*tgone_port);
                 
    tgtwo_addrpt->sin_addr.s_addr = inet_addr(tgfinal_host);
    tgtwo_addrpt->sin_family = AF_INET;
    tgtwo_addrpt->sin_port = htons(*tgone_port);
                 
    if(connect(tgsec->one_tgt_sockcheck,( struct sockaddr*)tgtone_addrpt,
        sizeof(*tgtone_addrpt)) < 0)
        printf("\n\t%s:%u closed\n", tgprimal_host, *tgone_port);   
    else
        printf("\n\t%s:%u open\n", tgprimal_host, *tgone_port);
                 
    if(connect(tgsec->one_tgt_sockcheck,( struct sockaddr*)tgtwo_addrpt,
        sizeof(*tgtwo_addrpt)) < 0)
        printf("\n\t%s:%u closed\n", tgfinal_host, *tgone_port);
    else
        printf("\n\t%s:%u open\n", tgfinal_host, *tgone_port);
    condition_tgtfinished = 1;
     
    if(*successfull_baby)
        printf("\nScan finished successfully!\n");
     
    close(tgsec->one_tgt_sockcheck);
         
    return 0;
             
}
 
// to scan three hosts
static uint8_t*
scan_three_hosts(const uint8_t *first_ip, const uint8_t *second_ip, 
const uint8_t *third_ip, uint32_t *three_port)
{
    conection *three_struct;
    three_struct = malloc(sizeof(conection));
     
    struct sockaddr_in *third_addr_first;
    struct sockaddr_in *third_addr_sec;
    struct sockaddr_in *third_addr_thrd;
 
    third_addr_first = (struct sockaddr_in*)malloc(sizeof(*third_addr_first));
    third_addr_sec   = (struct sockaddr_in*)malloc(sizeof(*third_addr_sec));
    third_addr_thrd  = (struct sockaddr_in*)malloc(sizeof(*third_addr_thrd));
 
    uint32_t thirdhosts_err;
    uint32_t *great_scan_sexy, sexy_value = 0; // I know.. I know what you're thinking!... No, actually I don't.
     
    great_scan_sexy = &sexy_value;
     
    if((three_struct->third_host_check = socket(AF_INET, SOCK_STREAM, 0)) == -1){
        thirdhosts_err = netsock_initializationfail("Unable to connect");
    }
     
    printf("\nScanning: %s - %s - %s:%u", first_ip, second_ip, 
                                            third_ip, *three_port);
     
    third_addr_first->sin_addr.s_addr = inet_addr(first_ip);
    third_addr_first->sin_family = AF_INET;
    third_addr_first->sin_port = htons(*three_port);
     
    third_addr_sec->sin_addr.s_addr = inet_addr(second_ip);
    third_addr_sec->sin_family = AF_INET;
    third_addr_sec->sin_port = htons(*three_port);
     
    third_addr_thrd->sin_addr.s_addr = inet_addr(third_ip);
    third_addr_thrd->sin_family = AF_INET;
    third_addr_thrd->sin_port = htons(*three_port);
     
    if(connect(three_struct->third_host_check, (struct sockaddr*)third_addr_first,
        sizeof(*third_addr_first)) < 0)
        printf("\n\t%s:%u closed\n", first_ip, *three_port);
    else
        printf("\n\t%s:%u open\n", first_ip, *three_port);
         
    if(connect(three_struct->third_host_check, (struct sockaddr*)third_addr_sec,
        sizeof(*third_addr_sec)) < 0)
        printf("\n\t%s:%u closed\n", second_ip, *three_port);
    else
        printf("\n\t%s:%u open\n", second_ip, *three_port);
         
    if(connect(three_struct->third_host_check, (struct sockaddr*)third_addr_thrd,
        sizeof(*third_addr_thrd)) < 0)
        printf("\n\t%s:%u closed\n", third_ip, *three_port);
    else
        printf("\n\t%s:%u open\n", third_ip, *three_port);
     
    sexy_value = 1;
     
    if(*great_scan_sexy)
        printf("\nScan finished successfully!\n");
     
    close(three_struct->third_host_check);
         
        return 0;
     
}
 
// scan four hosts
static uint8_t*
scan_four_hosts(const uint8_t *fscfhost, const uint8_t *fscshost, 
const uint8_t *fscthost, const uint8_t *fscfthhost, uint32_t *frthport)
{
    conection *frthcon;
    frthcon = malloc(sizeof(conection));
     
    struct sockaddr_in frst_addr;
    struct sockaddr_in scnd_addr;
    struct sockaddr_in thrd_addr;
    struct sockaddr_in frth_addr;
     
    uint32_t geterror_frth;
    uint32_t *frthhostscansuccess, frthhostscansuccessv = 0;
     
    frthhostscansuccess = &frthhostscansuccessv;
     
    if((frthcon->frth_host_check = socket(AF_INET, SOCK_STREAM, 0)) == -1){
        geterror_frth = netsock_initializationfail("Unable to connect");
    }
     
    printf("\nScanning: %s - %s - %s - %s:%u\n", fscfhost, fscshost, 
                                        fscthost, fscfthhost, *frthport);
     
    frst_addr.sin_addr.s_addr = inet_addr(fscfhost);
    frst_addr.sin_family = AF_INET;
    frst_addr.sin_port = htons(*frthport);
     
    scnd_addr.sin_addr.s_addr = inet_addr(fscshost);
    scnd_addr.sin_family = AF_INET;
    scnd_addr.sin_port = htons(*frthport);
     
    thrd_addr.sin_addr.s_addr = inet_addr(fscthost);
    thrd_addr.sin_family = AF_INET;
    thrd_addr.sin_port = htons(*frthport);
     
    frth_addr.sin_addr.s_addr = inet_addr(fscfthhost);
    frth_addr.sin_family = AF_INET;
    frth_addr.sin_port = htons(*frthport);
  
    if(connect(frthcon->frth_host_check, (struct sockaddr*)&frst_addr, 
        sizeof(frst_addr)) < 0)
        printf("\n\t%s:%u closed\n", fscfhost, *frthport);
    else
        printf("\n\t%s:%u open\n", fscfhost, *frthport);
         
    if(connect(frthcon->frth_host_check, (struct sockaddr*)&scnd_addr, 
        sizeof(scnd_addr)) < 0)
        printf("\n\t%s:%u closed\n", fscshost, *frthport);
    else
        printf("\n\t%s:%u open\n", fscshost, *frthport);
     
    if(connect(frthcon->frth_host_check, (struct sockaddr*)&thrd_addr, 
        sizeof(thrd_addr)) < 0)
        printf("\n\t%s:%u closed\n", fscthost, *frthport);
    else
        printf("\n\t%s:%u open\n", fscthost, *frthport);
     
    if(connect(frthcon->frth_host_check, (struct sockaddr*)&frth_addr, 
        sizeof(frth_addr)) < 0)
        printf("\n\t%s:%u closed\n", fscfthhost, *frthport);
    else
        printf("\n\t%s:%u open\n", fscfthhost, *frthport);
     
    frthhostscansuccessv = 1;   
         
    if(*frthhostscansuccess)
        printf("\nScan finished successfully!\n");
         
        close(frthcon->frth_host_check);
     
        return 0;
         
}
 
//scan five hosts
static uint8_t *scan_five(const uint8_t *fif_firsthost, const uint8_t *fif_sechost, 
const uint8_t *fif_thrdhost, const uint8_t *fif_frthhost, const uint8_t *fif_fifhost, 
                                                        uint32_t *fif_port)
{
    conection *fifcon;
    fifcon = malloc(sizeof(conection));
     
    struct sockaddr_in *fif_frstaddr;
    struct sockaddr_in *fif_secaddr;
    struct sockaddr_in *fif_thrdaddr;
    struct sockaddr_in *fif_frthaddr;
    struct sockaddr_in *fif_fifaddr;
     
    fif_frstaddr = (struct sockaddr_in*)malloc(sizeof(*fif_frstaddr));
    fif_secaddr  = (struct sockaddr_in*)malloc(sizeof(*fif_secaddr));
    fif_thrdaddr = (struct sockaddr_in*)malloc(sizeof(*fif_thrdaddr));
    fif_frthaddr = (struct sockaddr_in*)malloc(sizeof(*fif_frthaddr));
    fif_fifaddr  = (struct sockaddr_in*)malloc(sizeof(*fif_fifaddr));
     
    uint32_t getfiferrmsg;
    uint32_t *fifscandone, fifscandonev = 0;
 
    fifscandone = &fifscandonev;
         
    if((fifcon->fif_host_check = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        getfiferrmsg = netsock_initializationfail("Unable to connect");
    }
     
    printf("\nScanning %s - %s - %s - %s - %s:%u\n", fif_firsthost, fif_sechost, 
                            fif_thrdhost, fif_frthhost, fif_fifhost, *fif_port);
         
        fif_frstaddr->sin_addr.s_addr = inet_addr(fif_firsthost);
        fif_frstaddr->sin_family = AF_INET;
        fif_frstaddr->sin_port = htons(*fif_port);
         
        fif_secaddr->sin_addr.s_addr = inet_addr(fif_sechost);
        fif_secaddr->sin_family = AF_INET;
        fif_secaddr->sin_port = htons(*fif_port);
         
        fif_thrdaddr->sin_addr.s_addr = inet_addr(fif_thrdhost);
        fif_thrdaddr->sin_family = AF_INET;
        fif_thrdaddr->sin_port = htons(*fif_port);
         
        fif_frthaddr->sin_addr.s_addr = inet_addr(fif_frthhost);
        fif_frthaddr->sin_family = AF_INET;
        fif_frthaddr->sin_port = htons(*fif_port);
         
        fif_fifaddr->sin_addr.s_addr = inet_addr(fif_fifhost);
        fif_fifaddr->sin_family = AF_INET;
        fif_fifaddr->sin_port = htons(*fif_port);
         
        if(connect(fifcon->fif_host_check, (struct sockaddr*)fif_frstaddr,
        sizeof(*fif_frstaddr)) < 0)
            printf("\n\t%s:%u closed\n", fif_firsthost, *fif_port);
        else
            printf("\n\t%s:%u open\n", fif_firsthost, *fif_port);
         
        if(connect(fifcon->fif_host_check, (struct sockaddr*)fif_secaddr,
        sizeof(*fif_secaddr)) < 0)
            printf("\n\t%s:%u closed\n", fif_sechost, *fif_port);
        else
            printf("\n\t%s:%u open\n", fif_sechost, *fif_port);
         
        if(connect(fifcon->fif_host_check, (struct sockaddr*)fif_thrdaddr,
        sizeof(*fif_thrdaddr)) < 0)
            printf("\n\t%s:%u closed\n", fif_thrdhost, *fif_port);
        else
            printf("\n\t%s:%u open\n", fif_thrdhost, *fif_port);
         
        if(connect(fifcon->fif_host_check, (struct sockaddr*)fif_frthaddr,
        sizeof(*fif_frthaddr)) < 0)
            printf("\n\t%s:%u closed\n", fif_frthhost, *fif_port);
        else
            printf("\n\t%s:%u open\n", fif_frthhost, *fif_port);
         
        if(connect(fifcon->fif_host_check, (struct sockaddr*)fif_fifaddr,
        sizeof(*fif_fifaddr)) < 0)
            printf("\n\t%s:%u closed\n", fif_fifhost, *fif_port);
         
        fifscandonev = 1;
         
        if(*fifscandone)
            printf("\nScan finished successfully!\n");
         
        close(fifcon->fif_host_check);
         
        return 0;
}
 
// check if server runs FTP
static uint32_t 
checkserv_ftp(conection *ftpc, const uint8_t *ftp_host)
{
    // free ftpc memory
    ftpc = malloc(sizeof(conection));
     
    uint32_t ftperr;
    uint32_t *ftp_port;
    uint32_t default_ftprotnum = 21;
     
    ftp_port = &default_ftprotnum;
     
    struct sockaddr_in ftpconaddr;
    struct sockaddr_in *ftpconaddrpt;
     
    ftpconaddrpt = &ftpconaddr;
    ftpconaddrpt = (struct sockaddr_in*)malloc(sizeof(*ftpconaddrpt));
     
    uint32_t *ftp_endmsg, ftp_endmsgcheck = 0;
    ftp_endmsg = &ftp_endmsgcheck;
     
    if((ftpc->ftp_concheck = socket(AF_INET, SOCK_STREAM, 0)) == -1){
        ftperr = netsock_initializationfail("Unable to connect");
    }
     
    printf("\nScanning if %s runs FTP\n", ftp_host);
     
    ftpconaddrpt->sin_addr.s_addr = inet_addr(ftp_host);
    ftpconaddrpt->sin_family = AF_INET;
    ftpconaddrpt->sin_port = htons(*ftp_port);
     
    if(connect(ftpc->ftp_concheck, (struct sockaddr*)ftpconaddrpt,
    sizeof(*ftpconaddrpt)) < 0)
        printf("\n\t%s:%u closed - FTP does not run on this server\n", ftp_host, *ftp_port);
    else
        printf("\n\t%s:%u open - FTP does run on this server\n", ftp_host, *ftp_port);
     
    ftp_endmsgcheck = 1;
     
    if(*ftp_endmsg)
        printf("\nScan finished successfully\n");
     
    close(ftpc->ftp_concheck);
     
    return 0;
}
 
// check if server runs SSH
static uint32_t 
checkserv_ssh(conection *sshcon, const uint8_t *ssh_host)
{
    // free memory of sshcon
    sshcon = malloc(sizeof(conection));
    struct sockaddr_in *sshaddr;
    sshaddr = (struct sockaddr_in*)malloc(sizeof(*sshaddr));
    uint32_t getssherr, *sshport, *sshfin, sshfinv = 0, sshportv = 22;
     
    sshport = &sshportv;
    sshfin = &sshfinv;   
  
    if((sshcon->ssh_concheck = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        getssherr = netsock_initializationfail("Unable to connect");
    }
     
    printf("\nScanning if %s runs SSH\n", ssh_host);
     
    sshaddr->sin_addr.s_addr = inet_addr(ssh_host);
    sshaddr->sin_family = AF_INET;
    sshaddr->sin_port = htons(*sshport);
     
    if(connect(sshcon->ssh_concheck, (struct sockaddr*)sshaddr,
    sizeof(*sshaddr)) < 0)
       printf("\n\t%s:%u closed - SSH does not run on this server\n", ssh_host, *sshport);
    else
        printf("\n\t%s:%u open - SSH does run on this server\n", ssh_host, *sshport);
     
    sshfinv = 1;
     
    if(*sshfin)
        printf("\nScan finished successfully\n");
     
    close(sshcon->ssh_concheck);
     
    return 0;
}
 
// check if server runs smtp (usually port 25)
static uint32_t 
checkserv_smtp(conection *smtpc, const uint8_t *smtp_host)
{
    // free memory of smtpc
    smtpc = malloc(sizeof(conection));
    struct sockaddr_in *smtpaddr;
    smtpaddr = (struct sockaddr_in*)malloc(sizeof(*smtpaddr));
 
    uint32_t *smtpfin, *smtp_port, smtperr, smtpfinv = 0, smtp_portv = 25;
     
    smtp_port = &smtp_portv;   
    smtpfin = &smtpfinv;
 
    if((smtpc->smtp_conchecck = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        smtperr = netsock_initializationfail("Unable to connect");
    }
     
    printf("\nScanning if %s runs SMTP\n", smtp_host);
     
    smtpaddr->sin_addr.s_addr = inet_addr(smtp_host);
    smtpaddr->sin_family = AF_INET;
    smtpaddr->sin_port = htons(*smtp_port);
     
    if(connect(smtpc->smtp_conchecck, (struct sockaddr*)smtpaddr,
    sizeof(*smtpaddr)) < 0)
        printf("\n\t%s:%u closed - SMTP does not run on this server\n", smtp_host, *smtp_port);
    else
        printf("\n\t%s:%u open - SMTP does run on this server\n", smtp_host, *smtp_port);
     
    smtpfinv = 1;
     
    if(*smtpfin)
        printf("\nScan finished successfully!\n");
     
    close(smtpc->smtp_conchecck);
     
    return 0;
}
 
//check if server runs http
static uint32_t 
checkserv_http(conection *httpcon, const uint8_t *http_host)
{
    // again, free memory by using malloc
    httpcon = malloc(sizeof(conection));
     
    struct sockaddr_in *httpaddr;
    httpaddr = (struct sockaddr_in*)malloc(sizeof(*httpaddr));    
 
    uint32_t *httpfin, *http_port, httperr;
    uint32_t httpfinv = 0, http_portv = 80;
     
    http_port = &http_portv;
    httpfin = &httpfinv;
 
    if((httpcon->http_concheck = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        httperr = netsock_initializationfail("Unable to connect");
    }
     
    printf("\nScanning if %s runs HTTP\n", http_host);
     
    httpaddr->sin_addr.s_addr = inet_addr(http_host);
    httpaddr->sin_family = AF_INET;
    httpaddr->sin_port = htons(*http_port);
     
    if(connect(httpcon->http_concheck, (struct sockaddr*)httpaddr, 
    sizeof(*httpaddr)) < 0)
        printf("\n\t%s:%d closed - HTTP does not run on this server\n", http_host, *http_port);
    else
        printf("\n\t%s:%d open - HTTP does run on this server\n", http_host, *http_port);
     
    httpfinv = 1;
     
    if(*httpfin)
        printf("\nScan finished successfully!\n");
     
    close(httpcon->http_concheck);
    return 0;
}
 
// check if server runs https
static uint32_t 
checkserv_https(conection *httpscon, const uint8_t *https_host)
{
        // free memory
    httpscon = malloc(sizeof(conection));
    struct sockaddr_in *httpsaddr;
    httpsaddr = (struct sockaddr_in*)malloc(sizeof(*httpsaddr));
     
    uint32_t *httpsfin, *https_port, httpserr;
    uint32_t httpsfinv = 0, https_portv = 443;
 
    https_port = &https_portv;
    httpsfin = &httpsfinv;
 
    if ((httpscon->https_concheck = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        httpserr = netsock_initializationfail("Unable to connect");
    }
     
    printf("\nScanning if %s runs HTTPS\n", https_host);
 
    httpsaddr->sin_addr.s_addr = inet_addr(https_host);
    httpsaddr->sin_family = AF_INET;
    httpsaddr->sin_port = htons(*https_port);
 
    if (connect(httpscon->https_concheck, (struct sockaddr*)httpsaddr,
        sizeof(*httpsaddr)) < 0)
            printf("\n\t%s:%d closed - HTTPS does not run on this server\n", https_host, *https_port);
    else
            printf("\n\t%s:%d open - HTTPS does run on this server\n", https_host, *https_port);
 
    httpsfinv = 1;
 
    if (*httpsfin)
        printf("\nScan finished successfully!\n");
 
    close(httpscon->https_concheck);
    return 0;
 
}
 
int
main(int argc, uint8_t* argv[])
{
 
   static uint32_t *signle_successful_scan, txStartpot_argvalue;
   static uint32_t txEndport_argvalue, txDesttextfile_argvalue;
   static uint32_t tgStartport_argvalue, err_sock, tgDesthost_endargvalue; //tx for the text file
   static uint32_t tgEndport_argvalue, *tgDesthost_halue; // tg for targeted
   static uint32_t *ptProgram_instructionusage, sDesthost_endargvalue;
   static uint32_t sStartport_argvalue, sEndport_argvalue; // s for single
   // values for the localhost..
   static uint32_t lhoststartvalue, lhostendvalue;
   // continuation of target and text values
   static uint32_t value = 0;
   static uint32_t tgDesthost_startargvalue = 1;
   static uint32_t tgDesthost_lessthanvalue = 3;
   static uint32_t tgStartpot_lessthanvalue = 4;
   static uint32_t tgEndport_lessthanvalue = 5;
   static uint32_t txDesttextfile_lessthanvalue = 3;
   static uint32_t principal_instructionvariable = 0;
   static uint32_t principal_programusagecall; 
   // continue here...
   static uint32_t localstarport_lessthanvalue = 3;
   static uint32_t localendport_lessthanvalue = 4;
   static uint32_t txStartport_lessthanvalue = 4;
   static uint32_t txEndport_lessthanvalue = 5;
   static uint32_t loadtextfile_argumentvalue = 0;
   static uint32_t loadtextfile_sumargvalue = 1;
   static uint16_t sDesthost_lessthanvalue = 2;
   static uint16_t sStartport_lessthanvalue = 3;
   static uint16_t  sEndport_lessthanvalue = 4;
    
   static uint16_t *localhost_optionparsesubvalue;
   static uint16_t *localhost_optionparseaddvalue;
   static uint16_t localhost_optfirstsubvalue = 0;
   static uint16_t localhost_optsecsaddvalue = 1;
   // for the one port variables..
   static uint32_t *oneportfirstoptvalue, one_argvalue = 1;
   static uint32_t oneportsecoptvalue = 3;
   static uint32_t oneportthrdvalue = 4;
   static uint32_t oneport_hostvalue;
   static uint32_t oneport_portvalue;
    
   oneportfirstoptvalue = &one_argvalue;
    
   static int32_t ownnet_call;
   static uint8_t *sf_call, *tgt_call, *sone_call;
   static uint8_t *thrd_hostcheck_call, *frth_hostcheck_call, *fif_sc;
    
   uint32_t otgz = 0, otgf, otgs, otgt, otg_call;
   uint32_t otgf_value = 3, otgs_value = 4, otgt_value = 5;
    
   uint32_t thrd_hostcheckzlp = 1, thrd_hostcheckflp, thrd_hostchecsflp;
   uint32_t thrd_hostchecktlp;
   uint32_t thrd_hostcheckfifthlp;
   uint32_t thrd_hostcheckzlpcpt = 0, *ptthrd_hostcheckzlp;
   uint32_t *ptthrd_hostcheckzlpcpt;
   uint32_t thrd_fvalue = 3, thrd_svalue = 4;
   uint32_t thrd_frth_value = 5, thrd_fif_value = 6;
    
   // initialized fourth scan variable for argv[1];
   uint32_t frth_hostcheckzlp = 1;
   uint32_t frth_hostcheckflp, frth_hostcheckslp, frth_hostcheckthrdlp; 
   uint32_t frth_hostcheckfourthlp, frth_hostcheckfiflp;
 
   // first, second, third, fifth, sixth
   uint32_t frth_hostcheckflp_v = 3, frth_hostcheckslp_v = 4;
   uint32_t frth_hostcheckthrdlp_v = 5, frth_hostcheckfourthlp_v = 6;
   uint32_t frth_hostcheckfiflp_v = 7;
 
   //fif variables
   uint32_t fif_hostz = 1, fif_hostfirst, fif_hostsec, fif_hostthree;
   uint32_t fif_hostfour, fif_hostfive, fif_destport;
   uint32_t fif_hostfirst_v = 3, fif_hostsec_v = 4, fif_hostthree_v = 5;
   uint32_t fif_hostfour_v = 6,  fif_hostfive_v = 7, fif_destport_v = 8;
   // pointer to integer
   uint32_t cftpcall, csshcall, csmtpcall;
   ptProgram_instructionusage = &principal_instructionvariable;
    
   ptthrd_hostcheckzlp = &thrd_hostcheckzlp;
   ptthrd_hostcheckzlpcpt = &thrd_hostcheckzlpcpt;
    
   localhost_optionparsesubvalue = &localhost_optfirstsubvalue;
   localhost_optionparseaddvalue = &localhost_optsecsaddvalue;
   signle_successful_scan = &value; // for the pointer value
    
   //for the ftp protocol check
  static uint32_t *ftpoptarg, ftpoptargv = 1;
  static uint32_t ftploold, ftploomd = 3;
  ftpoptarg = &ftpoptargv;
  // for the ssh protocol check
  static uint32_t *sshoptarg, sshoptargv = 1;
  static uint32_t sshloold, sshloomd = 3;
  sshoptarg = &sshoptargv;
  // for the smtp protocol check
  static uint32_t *smtpoptarg, smtpoptargv = 1;
  static uint32_t smtploold, smtploomd = 3;
  smtpoptarg = &smtpoptargv;
  // for the http protocol check
  static uint32_t *httpoptarg, httpoptargv = 1;
  static uint32_t httploold, httploomd = 3;
  httpoptarg = &httpoptargv;
  // for the https protocol check
  static uint32_t *httpsoptarg, httpsoptargv = 1;
  static uint32_t httpsloold, httpsloomd = 3;
  httpsoptarg = &httpsoptargv;
  // for the three ports specification check
  static uint32_t *threeoptarg, threeoptargv = 1;
  static uint32_t threefloold, threefloomd = 3;
  static uint32_t threeflooldsc, threefloomdsc = 4;
  static uint32_t threeflooldtd, threefloomdtd = 5;
  static uint32_t threeflooldft, threefloomdft = 6;
  threeoptarg = &threeoptargv;
   
   struct sockaddr_in *standard_addr;
   struct sockaddr_in *onftp_detect;
   struct sockaddr_in *onssh_detect;
   struct sockaddr_in *http_detect;
    
   standard_addr = (struct sockaddr_in*)malloc(sizeof(*standard_addr));
   onftp_detect  = (struct sockaddr_in*)malloc(sizeof(*onftp_detect));
   onssh_detect  = (struct sockaddr_in*)malloc(sizeof(*onssh_detect));
   http_detect   = (struct sockaddr_in*)malloc(sizeof(*http_detect));
    
   struct MultiHostsBool mhbcss;
    
   conection *conc;
   conection *accessor;
   conection *thrd_get;
   conection *frth_get;
   conection *fif_get;
   second *on_tg;
   second *frth_psc;
   conection *ftpcss;
   conection *sshcss;
   conection *smtpcss;
   conection *httpcss;
   conection *httpscss;
   conection *threecss;
   conection *frthcss;
   // free some memory
   conc = malloc(sizeof(conection));
   accessor = malloc(sizeof(conection));
   thrd_get = malloc(sizeof(conection));
   frth_get = malloc(sizeof(conection));
   fif_get =  malloc(sizeof(conection));
   ftpcss = malloc(sizeof(conection));
   sshcss = malloc(sizeof(conection));
   httpcss = malloc(sizeof(conection));
   httpscss = malloc(sizeof(conection));
   threecss = malloc(sizeof(conection));
   frthcss  = malloc(sizeof(frthcss));
   on_tg = malloc(sizeof(second));
   frth_psc = malloc(sizeof(second));
   // variables to scan four ports on one host
   struct MultiPortsBools mpbftstct;
   uint32_t frthz = 1, frthf, frthsc, frthtd, frthft, frthfv;
 
    
   accessor->principal_zerovalue = 0;
   accessor->ptprincipal_zerovalue = &accessor->principal_zerovalue;
     
   if(argc != 3 && argc != 4 && argc != 5 && argc != 6 && argc != 7 && argc != 8){
 
       principal_programusagecall = program_usage(argv[*ptProgram_instructionusage]);
     
   }
    
   else if(argc == 3)
   {
       if(strncmp(argv[*ftpoptarg], "-cftp", strlen("-cftp")) == 0)
       {
           for(ftploold = *accessor->ptprincipal_zerovalue;
           ftploold < ftploomd; ftploold++){
                ftpcss->ftpcheckhost = argv[ftploold];
           }
            
           cftpcall = checkserv_ftp(ftpcss, ftpcss->ftpcheckhost);
           exit(EXIT_SUCCESS);
       }
       else if(strncmp(argv[*sshoptarg], "-cssh", strlen("-cssh")) == 0)
       {
           for(sshloold = *accessor->ptprincipal_zerovalue;
               sshloold < sshloomd; sshloold++){
               sshcss->sshcheckhost = argv[sshloold];                              
            }
            
           csshcall = checkserv_ssh(sshcss, sshcss->sshcheckhost);
           exit(EXIT_SUCCESS);
       }
       else if (strncmp(argv[*smtpoptarg], "-csmtp", strlen("-cstmp")) == 0)
       {
           for (smtploold = *accessor->ptprincipal_zerovalue;
                        smtploold < smtploomd; smtploold++) {
               smtpcss->smtpcheckhost = argv[smtploold];
           }
 
           csmtpcall = checkserv_smtp(smtpcss, smtpcss->smtpcheckhost);
           exit(EXIT_SUCCESS);
       }
           else if(strncmp(argv[*httpoptarg], "-chttp", strlen("-chttp")) == 0)
           {
               for (httploold = *accessor->ptprincipal_zerovalue;
                    httploold < httploomd; httploold++) {
               httpcss->httpcheckhost = argv[httploold];
                }
 
           checkserv_http(httpcss, httpcss->httpcheckhost);
           exit(EXIT_SUCCESS);
           }
           else if(strncmp(argv[*httpsoptarg], "-cssl", strlen("-ssl")) == 0)
           {
               for (httpsloold = *accessor->ptprincipal_zerovalue;
                    httpsloold < httpsloomd; httpsloold++) {
               httpscss->httpscheckhost = argv[httpsloold];
           }
 
           checkserv_https(httpscss, httpscss->httpscheckhost);
           exit(EXIT_SUCCESS);
           }
            
   }
    
   else if(argc == 4) 
   {
             
        if(strncmp(argv[*localhost_optionparsesubvalue + *localhost_optionparseaddvalue], "-lh", strlen("-lh")) == 0) 
                {
                 
                for(lhoststartvalue = *accessor->ptprincipal_zerovalue; 
                                lhoststartvalue < localstarport_lessthanvalue; 
                                lhoststartvalue++){
                    conc->starting_port = atoi(argv[lhoststartvalue]);
                                }
                                for(lhostendvalue = *accessor->ptprincipal_zerovalue;
                                lhostendvalue < localendport_lessthanvalue;
                                lhostendvalue++){
                                    conc->ending_port = atoi(argv[lhostendvalue]);
                }
                 
                ownnet_call = scanownnetwork_localghost(conc->starting_port,
                                                                           conc->ending_port);
                exit(EXIT_SUCCESS);
        }
        else if(strncmp(argv[*oneportfirstoptvalue], "-port=1", strlen("-port=1")) == 0) 
                {
             
            for(oneport_hostvalue = *accessor->ptprincipal_zerovalue;
                        oneport_hostvalue < oneportsecoptvalue;
                        oneport_hostvalue++){
                            conc->desthost_oneport = argv[oneport_hostvalue];
            }
                 
            for(oneport_portvalue = *accessor->ptprincipal_zerovalue;
                        oneport_portvalue < oneportthrdvalue;
                        oneport_portvalue++){
                            conc->oneport_startport = atoi(argv[oneport_portvalue]);
            }
                 
            sone_call = oneopenport_hostheck(conc->desthost_oneport, 
                                                      &conc->oneport_startport);
            exit(EXIT_SUCCESS);
        }
   }
     
   else if(argc == 5) 
   {
                         if(strncmp(argv[otgz + 1], "-2", strlen("-2")) == 0)  
                        {
                // 2nd argument
                for(otgf = *accessor->ptprincipal_zerovalue;
                                    otgf < otgf_value; otgf++){
                    on_tg->tgt_desthost_primal = argv[otgf];
                }
                for(otgs = *accessor->ptprincipal_zerovalue;
                                    otgs < otgs_value; otgs++){
                    on_tg->tgt_desthost_final = argv[otgs];
                }
                for(otgt = *accessor->ptprincipal_zerovalue;
                                    otgt < otgt_value; otgt++){
                    on_tg->nonpt_tgt_dest_port = atoi(argv[otgt]);
                }
                 
                otg_call = oneport_tartetedhostcheck(mhbcss, 
                                on_tg->tgt_desthost_primal, 
                                on_tg->tgt_desthost_final, 
                                &on_tg->nonpt_tgt_dest_port);
                exit(EXIT_SUCCESS);
                        }
                           
        tgDesthost_halue = &tgDesthost_startargvalue;
        // ^ as pointer value used bellow as first argument
        conc->targethost_scan = argv[*tgDesthost_halue];
         
        for(tgDesthost_endargvalue = *accessor->ptprincipal_zerovalue;
                tgDesthost_endargvalue<tgDesthost_lessthanvalue;
                tgDesthost_endargvalue++)
                {
            conc->end_targethost_scan = argv[tgDesthost_endargvalue];
        }   
             
        for(tgStartport_argvalue = *accessor->ptprincipal_zerovalue;
                tgStartport_argvalue<tgStartpot_lessthanvalue; tgStartport_argvalue++)
        {
            conc->starting_port = atoi(argv[tgStartport_argvalue]);
        }
         
        for(tgEndport_argvalue= *accessor->ptprincipal_zerovalue; 
                tgEndport_argvalue<tgEndport_lessthanvalue; tgEndport_argvalue++)
        {
            conc->ending_port = atoi(argv[tgEndport_argvalue]);
        }
         
        conc->targeted_startport = &conc->starting_port;
        conc->targeted_endport = &conc->ending_port;
 
        tgt_call = perform_targeted_scan(conc->targethost_scan, 
                conc->end_targethost_scan, *conc->targeted_startport, 
                                              *conc->targeted_endport);
        exit(EXIT_SUCCESS);
 
   }
   else if(argc == 6)
   {
     if(strncmp(argv[*ptthrd_hostcheckzlp + *ptthrd_hostcheckzlpcpt], "-3", strlen("-3")) == 0)
         {
             // the call to scan three hosts
        for(thrd_hostcheckflp = *accessor->ptprincipal_zerovalue; 
                thrd_hostcheckflp < thrd_fvalue; thrd_hostcheckflp++)
        {
                    thrd_get->threehosts_desthost_first = argv[thrd_hostcheckflp];
        }
             
        for(thrd_hostchecsflp = *accessor->ptprincipal_zerovalue;
                thrd_hostchecsflp < thrd_svalue; thrd_hostchecsflp++)
        {
                    thrd_get->threehosts_desthost_second = argv[thrd_hostchecsflp];
        }
             
        for(thrd_hostchecktlp = *accessor->ptprincipal_zerovalue;
                thrd_hostchecktlp < thrd_frth_value; thrd_hostchecktlp++)
                {
                    thrd_get->threehosts_desthost_third = argv[thrd_hostchecktlp];
        }
             
        for(thrd_hostcheckfifthlp = *accessor->ptprincipal_zerovalue;
                thrd_hostcheckfifthlp < thrd_fif_value; thrd_hostcheckfifthlp++)
        {
                    thrd_get->thrdprt = atoi(argv[thrd_hostcheckfifthlp]);
        }
             
    thrd_hostcheck_call = scan_three_hosts(thrd_get->threehosts_desthost_first,
        thrd_get->threehosts_desthost_second, thrd_get->threehosts_desthost_third,
        &thrd_get->thrdprt);
            exit(EXIT_SUCCESS);
    }
        
     
    exit(EXIT_FAILURE); 
         
   }
   else if(argc == 7)
   {
        // first argument aka argv[1]
        if(strncmp(argv[frth_hostcheckzlp], "-4", strlen("-4")) == 0) 
                {
            for(frth_hostcheckflp = *accessor->ptprincipal_zerovalue;
                        frth_hostcheckflp < frth_hostcheckflp_v;
                        frth_hostcheckflp++)
                        {
                            frth_get->frth_firsthost = argv[frth_hostcheckflp];
                        }
            for(frth_hostcheckslp = *accessor->ptprincipal_zerovalue;
                        frth_hostcheckslp < frth_hostcheckslp_v;
                        frth_hostcheckslp++)
                        {
                            frth_get->frth_sechost = argv[frth_hostcheckslp];
            }
            for(frth_hostcheckthrdlp = *accessor->ptprincipal_zerovalue;
                        frth_hostcheckthrdlp < frth_hostcheckthrdlp_v;
                        frth_hostcheckthrdlp++)
                        {
                            frth_get->frth_thrdhost = argv[frth_hostcheckthrdlp];
            }
            for(frth_hostcheckfourthlp = *accessor->ptprincipal_zerovalue;
                        frth_hostcheckfourthlp < frth_hostcheckfourthlp_v;
                        frth_hostcheckfourthlp++)
                        {
                            frth_get->frth_frthhost = argv[frth_hostcheckfourthlp];
            }
            for(frth_hostcheckfiflp = *accessor->ptprincipal_zerovalue;
                        frth_hostcheckfiflp < frth_hostcheckfiflp_v; 
                        frth_hostcheckfiflp++)
                        {
                            frth_get->frthprt = atoi(argv[frth_hostcheckfiflp]);
            }
                 
                frth_hostcheck_call = scan_four_hosts(
                                        frth_get->frth_firsthost, 
                                        frth_get->frth_sechost, 
                    frth_get->frth_thrdhost, 
                                        frth_get->frth_frthhost,
                                        &frth_get->frthprt);
                exit(EXIT_SUCCESS);
        }
                 
        exit(EXIT_FAILURE);
         
   }
   // next argument host
   else if(argc == 8)
   {
       if(strncmp(argv[fif_hostz], "-5", strlen("-5")) == 0)
       {
           for(fif_hostfirst = *accessor->ptprincipal_zerovalue;
           fif_hostfirst < fif_hostfirst_v; fif_hostfirst++)
           {
               fif_get->fif_fifost = argv[fif_hostfirst];
           }
           for(fif_hostsec = *accessor->ptprincipal_zerovalue;
           fif_hostsec < fif_hostsec_v; fif_hostsec++)
           {
               fif_get->fif_secost = argv[fif_hostsec];
           }
           for(fif_hostthree = *accessor->ptprincipal_zerovalue;
           fif_hostthree < fif_hostthree_v; fif_hostthree++)
           {
               fif_get->fif_thirdost = argv[fif_hostthree];
           }
           for(fif_hostfour = *accessor->ptprincipal_zerovalue;
           fif_hostfour < fif_hostfour_v; fif_hostfour++)
           {
               fif_get->fif_fourost = argv[fif_hostfour];
           }
           for(fif_hostfive = *accessor->ptprincipal_zerovalue;
           fif_hostfive < fif_hostfive_v; fif_hostfive++)
           {
               fif_get->fif_fifost = argv[fif_hostfive];
           }
           for(fif_destport = *accessor->ptprincipal_zerovalue;
           fif_destport < fif_destport_v; fif_destport++)
           {
               fif_get->fifprt = atoi(argv[fif_destport]);
           }
            
           fif_sc = scan_five(fif_get->fif_fifost, fif_get->fif_secost, 
                   fif_get->fif_thirdost, fif_get->fif_fourost, 
                   fif_get->fif_fifost, &fif_get->fifprt);
           exit(EXIT_SUCCESS);
       }
        
       exit(EXIT_FAILURE);
        
   }
    
   //standard normal scan
    if((conc->sock_connectioncheck = socket(AF_INET, SOCK_STREAM, 0)) == -1){
        // error message if the socket fails
            err_sock = netsock_initializationfail("[-] Unable to create a socket");
         
    }
     
    for(sDesthost_endargvalue = *accessor->ptprincipal_zerovalue;
        sDesthost_endargvalue < sDesthost_lessthanvalue; sDesthost_endargvalue++)
    {
            conc->targethost_scan = argv[sDesthost_endargvalue];
    }
     
    for(sStartport_argvalue = *accessor->ptprincipal_zerovalue;
    sStartport_argvalue < sStartport_lessthanvalue; sStartport_argvalue++)
    {
            conc->starting_port = atoi(argv[sStartport_argvalue]);
    }
     
    for(sEndport_argvalue = *accessor->ptprincipal_zerovalue;
        sEndport_argvalue < sEndport_lessthanvalue; sEndport_argvalue++)
    {
            conc->ending_port = atoi(argv[sEndport_argvalue]);
    }
     
        conc->startport_destscan = &conc->starting_port;
    conc->endport_destscan   = &conc->ending_port;
     
    alert_signlescan("\nScanning: %s:%d/%d\n\n", conc->targethost_scan, 
                        *conc->startport_destscan, *conc->endport_destscan);
     
    onftp_detect->sin_addr.s_addr = inet_addr(conc->targethost_scan);
        onftp_detect->sin_family = AF_INET;
        onftp_detect->sin_port = htons(21);
         
        onssh_detect->sin_addr.s_addr = inet_addr(conc->targethost_scan);
        onssh_detect->sin_family = AF_INET;
        onssh_detect->sin_port = htons(22);
         
        http_detect->sin_addr.s_addr = inet_addr(conc->targethost_scan);
        http_detect->sin_family = AF_INET;
        http_detect->sin_port = htons(80);
         
        for(conc->final_port = conc->starting_port; conc->final_port <= conc->ending_port; conc->final_port++)
         for(conc->starting_port = conc->starting_port; 
             conc->starting_port<=conc->ending_port; conc->starting_port++) {
             
            standard_addr->sin_addr.s_addr = inet_addr(conc->targethost_scan);
            standard_addr->sin_family = AF_INET;
            standard_addr->sin_port = htons(conc->starting_port);
                         
        if(connect(conc->sock_connectioncheck,( struct sockaddr*)standard_addr,
                sizeof(*standard_addr)) < 0)
                printf("\n\t%s:%d/%d closed\n\n", conc->targethost_scan, conc->starting_port, conc->ending_port);
            else
                printf("\n\t%s:%d/%d open\n\n", conc->targethost_scan, conc->starting_port, conc->ending_port);
             
                         
        value = 1;
        // same boolean value as with the multi targeted scan
    }
     
    if(*signle_successful_scan)
        printf("\nScan terminated successfully\n");
         
       
    close(conc->sock_connectioncheck);
    free(conc);
    return 0;
}

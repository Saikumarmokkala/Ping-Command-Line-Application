// Name: SAI KUMAR REDDY MOKKALA

/*
Compilation Instructions:



Super user privileges are required to run the program. So,sudo is used.
gcc -o ping ping.c
sudo ./ping <host-name/IP address> 

or 

sudo ./ping <hostname|IP address> <Custom TTL> 

or 


sudo ./ping <hostname|IP address> <Custom TTL>  <4/6> 
4 is for ipv4 version whereas 6 is for ipv6 version (ipv4 - 4 / ipv6 - 6)


Debug run:
gcc -o ping ping.c
sudo ./ping www.cloudflare.com

or 

gcc -o ping ping.c
sudo ./ping www.cloudflare.com 34 // 34 is the custom Time to Live

or

gcc -o ping ping.c
sudo ./ping www.cloudflare.com 34  4 // 4 is the ipv4 version

or

gcc -o ping ping.c
sudo ./ping www.cloudflare.com 34  6 // 6 is the ipv6 version

Default mode is ipv4 if no ipversion is given



We will get the statistics of total messages from ctrl + c interruptor

*/

// Reference : https://www.geeksforgeeks.org/ping-in-c/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>
#include <setjmp.h>
#include <errno.h>




// Defining the variables 

#define PACKET_SIZE   4096   // Packet size

// Max Waittime

#define MAX_WAIT_TIME   5    


// Character arrays for send packet and receive packet
char sendpacket[PACKET_SIZE];

char recvpacket[PACKET_SIZE];





int sockfd, datalen = 56;  // Taking the data length

// Counters for send and receive messages.

int nsend = 0, nreceived = 0;


// Structure for the type ipv4
struct sockaddr_in dest_addr;

// Structure for the type ipv6
struct sockaddr_in6 dest_addr1;


// Process ID
pid_t pid;

struct sockaddr_in from;

struct timeval tvrecv;


// Function declarations

void stats(int signalNo);



unsigned short chksum(unsigned short *addr, int len);

int pack_icmp(int pack_no);

int unpack_icmp(char *buf, int len,int ttlabc, int ipabc);

void send_packet(void);

void recieve_packet(int ttlabc,int ipabc);

void tv_sub(struct timeval *out, struct timeval *in);


// Function for handling the infinite  loop when icmp packets are sent
void intrHandler(int proxy) 
{ 
    stats(SIGALRM);
} 


// Statistics are produced when we press ctrl+c (interruptor)
void stats(int signalNo) 
{

    printf("\n--------------------Statistics-------------------\n");
    printf("%d transmitted, %d received , %d Packets lost\n", nsend, nreceived,
    	(nsend - nreceived));

    // Closing the socket
    close(sockfd); 
    exit(1);
} 

// Checksum Calculation
unsigned short chksum(unsigned short *addr, int len) 
{

    int nleft = len;
    int sum = 0;

    unsigned short *w = addr;
    unsigned short answer = 0;

    while (nleft > 1) {
        sum +=  *w++;
        nleft -= 2;
    }


    if (nleft == 1) {
        *(unsigned char*)(&answer) = *(unsigned char*)w;
        sum += answer;
    }

    sum = (sum >> 16) + (sum &0xffff);
    sum += (sum >> 16);
    answer = ~sum;

    return answer;
}

// Packing ICMP

int pack_icmp(int pack_no) 
{

    int i, packsize;
    struct icmp *icmp;
    struct timeval *tval;

    // Intialization of values
    icmp = (struct icmp*)sendpacket;

    icmp->icmp_type = ICMP_ECHO;

    icmp->icmp_code = 0;

    icmp->icmp_cksum = 0;

    icmp->icmp_seq = pack_no;

    icmp->icmp_id = pid;

    packsize = 8+datalen;

    tval = (struct timeval*)icmp->icmp_data;

    gettimeofday(tval, NULL); 
    icmp->icmp_cksum = chksum((unsigned short*)icmp, packsize); 

    return packsize;
}

// Unpacking ICMP
int unpack_icmp(char *buf, int len,int ttlabc, int ipabc) 
{

   // Declaring variables
    int i, ip_header_len;

    struct ip *ip;

    struct icmp *icmp;

    struct timeval *tvsend;
    double rtt;

    ip = (struct ip*)buf;

    ip_header_len = ip->ip_hl << 2; 

    icmp = (struct icmp*)(buf + ip_header_len);

    len -= ip_header_len; 

    // if Length is less than 8
    if (len < 8) {
        printf("Length of the packet is less than 8\n");
        return  - 1;
    } 

   

    // Echo replies
    if ((icmp->icmp_type == ICMP_ECHOREPLY) && (icmp->icmp_id == pid)) 
    {
        tvsend = (struct timeval*)icmp->icmp_data;
        tv_sub(&tvrecv, tvsend); 
        rtt = tvrecv.tv_sec * 1000+tvrecv.tv_usec / 1000;
        int packets_lost = nsend - nreceived-1;
        //int ttl=ip->ip_ttl;
        // Calculating the lost percentage
        // Displaying for each message with packets lost and latency
        printf("%d byte from %s: icmp_seq=%u packets_lost=%d ttl=%d rtt=%.3f ms version :ipv%d\n", len,
        inet_ntoa(from.sin_addr), icmp->icmp_seq, packets_lost, ttlabc, rtt, ipabc);
    }

    else 
    {
        return  - 1;
    }
 }


// Sending the packets
void send_packet() 
{

    nsend++;
    int packetsize = pack_icmp(nsend); 
    if (sendto(sockfd, sendpacket, packetsize, 0, (struct sockaddr*) &dest_addr, sizeof(dest_addr)) < 0) 
    {
        perror("send packet error");
        return;
    }


    sleep(1); 
}

// Receiving the packets
void recieve_packet(int ttlabc, int ipabc) 

{

    int n, fromlen;
    extern int errno;
    // For displaying the statistics when ever the ctrl+c is pressed
    signal(SIGALRM, stats);
    fromlen = sizeof(from);

    alarm(MAX_WAIT_TIME);

    if ((n = recvfrom(sockfd, recvpacket, sizeof(recvpacket), 0, 
    	(struct sockaddr*) &from, &fromlen)) < 0) {
			if (errno == EINTR) {
                return;
			}
        perror("error in packet receive");
        return;
    } gettimeofday(&tvrecv, NULL); 

    if (unpack_icmp(recvpacket, n, ttlabc, ipabc) ==  - 1) {
   	    return;
    }

    nreceived++;
}

void tv_sub(struct timeval *out, struct timeval *in) 

{

    if ((out->tv_usec -= in->tv_usec) < 0) 
    {
        --out->tv_sec;
        out->tv_usec += 1000000;
    } 

    out->tv_sec -= in->tv_sec;
}

// Main Function

int main(int argc, char *argv[]) 

{

    struct hostent *host;  // Host

    // Declaration of protocol
    struct protoent *protocol; 

    // Default : for time to live and ipversion
    int ttl_val=64;
    int ip_val =4;
    unsigned long inaddr = 0l;

    int waittime = MAX_WAIT_TIME;
    int size = 23;

    // Output for user when ever less arguments are given in command line
    // Argument count is  less than 2
    if (argc < 2) 
    {

        printf("usage:%s <hostname|IP address> <Custom TTL>  <4/6> (ipv4 - 4 / ipv6 - 6)\n", argv[0]);
        exit(1);
    } 

    // If  argument count is equal to 3, we are setting custom Time to live

    if(argc == 3)
    {
        ttl_val = atoi(argv[2]);

        if(ttl_val == 0)
        {
            printf("TTL Value entered invalid! Defaulting to 64\n");
            ttl_val = 64;
        }

        else
        {
            printf("Custom TTL Value entered! TTL: %d\n", ttl_val);
        }
    }

    if ((protocol = getprotobyname("icmp")) == NULL) {

        perror("error in get protocol by name");
        exit(1);
    }

    if ((sockfd = socket(AF_INET, SOCK_RAW, protocol->p_proto)) < 0) 
    {

        perror("socket error");
        exit(1);
    }

    // Here it will run in default mode of ipv4 without giving custom TTL and custom ip version
   
    if(argc == 2)
    {
        setuid(getuid());
        setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
        bzero(&dest_addr, sizeof(dest_addr));
        
        // Default mode is ipv4
        dest_addr.sin_family = AF_INET;

        if (inaddr = inet_addr(argv[1]) == INADDR_NONE) 
        {

             if ((host = gethostbyname(argv[1])) == NULL) 
             {

               perror("error while trying to get host by name");
               exit(1);

             }
       
             memcpy((char*) &dest_addr.sin_addr, host->h_addr, host->h_length);
        } 

        else 
       {   
        
            dest_addr.sin_addr.s_addr = inet_addr(argv[1]);
       }

       // Getting the process ID
       pid = getpid();

       printf("PING %s(%s): \n", argv[1], inet_ntoa(dest_addr.sin_addr));

       signal(SIGINT, intrHandler);


       // Infinite loop for sending the icmp message packets

       while (1) 
       {
            send_packet(); 
            recieve_packet(ttl_val, ip_val); 
       }
   }
   
   // Here it will run in default mode of ipv4  with custom TTL

   if(argc == 3)
    {
      
       setuid(getuid());
       setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
       bzero(&dest_addr, sizeof(dest_addr));

       // Assigning the ipv4 version
       dest_addr.sin_family = AF_INET;
        
    if (inaddr = inet_addr(argv[1]) == INADDR_NONE) 
    {

        if ((host = gethostbyname(argv[1])) == NULL) 
        {

            perror("error while trying to get host by name");
            exit(1);

        }

        memcpy((char*) &dest_addr.sin_addr, host->h_addr, host->h_length);


    } 

    else 
    {
        
        dest_addr.sin_addr.s_addr = inet_addr(argv[1]);
    }

   
    // Getting the processs ID
    pid = getpid();

   
    printf("PING %s(%s): \n", argv[1], inet_ntoa(dest_addr.sin_addr));

    signal(SIGINT, intrHandler);
  

   // Infinite loop for sending icmp packets
    while (1) 
    {
        send_packet(); 
        recieve_packet(ttl_val, ip_val);
    }

   }

  // Here it will run in  custom TTL and custom versions of ip

 if(argc == 4)
{
         // Taking the value of ip version from command line
         ip_val = atoi(argv[3]);
   
        // If the ip version is 4
        if(ip_val == 4)
        {
               setuid(getuid());
               setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
               bzero(&dest_addr, sizeof(dest_addr));
               // Assigning the ip version
               dest_addr.sin_family = AF_INET;
               // Taking the time to live value from command line
               ttl_val = atoi(argv[2]);

              if (inaddr = inet_addr(argv[1]) == INADDR_NONE) 
              {

                  if ((host = gethostbyname(argv[1])) == NULL) 
                  {

                       perror("error while trying to get host by name");
                       exit(1);

                  }
        

                  memcpy((char*) &dest_addr.sin_addr, host->h_addr, host->h_length);
              }


           else 
           {
               dest_addr.sin_addr.s_addr = inet_addr(argv[1]);
           }

           pid = getpid();
           printf("PING %s(%s): \n", argv[1],
           inet_ntoa(dest_addr.sin_addr));


           // Interrupt handler
           signal(SIGINT, intrHandler);


            //Infinite loop for sending icmp packets
            while (1) 
            {
               send_packet(); 
               recieve_packet(ttl_val, ip_val); 
            }


        }

        // If the ipversion is ipv6

       else if(ip_val == 6)
      {
            setuid(getuid());
   // setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &ttl_val, sizeof(ttl_val));
            setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
            bzero(&dest_addr, sizeof(dest_addr));

            // Assigning the ip version
            dest_addr1.sin6_family = AF_INET6;

            //Taking the ipversion value from command line
            ttl_val = atoi(argv[2]);
 

            if (inaddr = inet_addr(argv[1]) == INADDR_NONE) 

            {

                    if ((host = gethostbyname(argv[1])) == NULL) 
                    {

                         perror("error while trying to get host by name");
                         exit(1);

                    }

                memcpy((char*) &dest_addr.sin_addr, host->h_addr, host->h_length);

             }


            else 
            {
        
                 dest_addr.sin_addr.s_addr = inet_addr(argv[1]);
            }

           // Getting the process ID
            pid = getpid();
            printf("PING %s(%s): \n", argv[1],
            inet_ntoa(dest_addr.sin_addr));
            
            // Interrupt handler

            signal(SIGINT, intrHandler);

            // Infinite loop for sending icmp packets

            while (1) 
            {
                send_packet(); 
                recieve_packet(ttl_val, ip_val); 
            }
        }

   }  
 
    return 0;

}

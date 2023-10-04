#include <iostream>
#include <fstream>
#include <string>
#include <random>
#include <thread>
#include <mutex>
#include <queue>
#include <unistd.h>
#include <time.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#define slow_start 1
#define congestion_avoidance 2
#define fast_recovery 3
#define Loss 10e-6
using namespace std;

class Packet
{
public:
    unsigned short Dest = 0;
    unsigned short Source = 0;
    unsigned int seq_num = 0;
    unsigned int ack_num = 0;
    unsigned int check_sum = 0;
    int data_size = 1024;
    int ACK = 0;
    bool END = 0;
    bool SYN = 0;
    bool FIN = 0;
    unsigned short window_size = 0;
    char data[1024];
};





mutex M;

int Rhead = 0, Rtail = 0;
int Rbuff_seat[512] = {0};
Packet Rbuff[512];

int Shead[2] = {0, -1}, Stail = 0;
int Sbuff_seat[512] = {0};
Packet Sbuff[512];

int sockfd;
struct sockaddr_storage their_addr;
socklen_t their_addr_len;


void receive()
{
    while (1)
    {
        Packet RcvPacket;
        recvfrom(sockfd, (char *)&RcvPacket, sizeof(RcvPacket), 0, (struct sockaddr *)&their_addr, &their_addr_len);
        if (RcvPacket.END)
        {
            Packet end;
            end.END = 1;
            sendto(sockfd, (char *)&end, sizeof(end), 0, (struct sockaddr *)&their_addr, their_addr_len);
            break;
        }
        M.lock();
        Rbuff_seat[Rtail] = 1;
        Rbuff[Rtail].Dest = RcvPacket.Dest;
        Rbuff[Rtail].Source = RcvPacket.Source;
        Rbuff[Rtail].seq_num = RcvPacket.seq_num;
        Rbuff[Rtail].ack_num = RcvPacket.ack_num;
        Rbuff[Rtail].check_sum = RcvPacket.check_sum;
        Rbuff[Rtail].data_size = RcvPacket.data_size;
        Rbuff[Rtail].END = RcvPacket.END;
        Rbuff[Rtail].ACK = RcvPacket.ACK;
        Rbuff[Rtail].SYN = RcvPacket.SYN;
        Rbuff[Rtail].FIN = RcvPacket.FIN;
        Rbuff[Rtail].window_size = RcvPacket.window_size;
        for (int i = 0; i < 1024; i++)
            Rbuff[Rtail].data[i] = RcvPacket.data[i];

        Rtail = (Rtail + 1) % 512;
        M.unlock();
    }
}

void reset_buff(int num)
{
    Sbuff[num].Dest = 0;
    Sbuff[num].Source = 0;
    Sbuff[num].seq_num = 0;
    Sbuff[num].ack_num = 0;
    Sbuff[num].check_sum = 0;
    Sbuff[num].data_size = 0;
    Sbuff[num].END = 0;
    Sbuff[num].ACK = 0;
    Sbuff[num].SYN = 0;
    Sbuff[num].FIN = 0;
    Sbuff[num].window_size = 0;
    for (int i = 0; i < 1024; i++)
        Sbuff[num].data[i] = 0;
}

void reset(Packet *p)
{
    p->Dest = 0;
    p->Source = 0;
    p->seq_num = 0;
    p->ack_num = 0;
    p->check_sum = 0;
    p->data_size = 1024;
    p->END = 0;
    p->ACK = 0;
    p->SYN = 0;
    p->FIN = 0;
    p->window_size = 0;
    memset(&p->data, 0, sizeof(p->data));
}

char *DNS(const char *aa, char *b)
{
    struct addrinfo hints;
    struct addrinfo *servinfo;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if (getaddrinfo(aa, NULL, &hints, &servinfo) != 0)
    {
        strcpy(b, "Invaild format or Invaild domain name.");
        return b;
    }

    struct sockaddr_in *ipv4 = (struct sockaddr_in *)servinfo->ai_addr;
    void *addr = &(ipv4->sin_addr);
    inet_ntop(hints.ai_family, addr, b, INET6_ADDRSTRLEN);
    return b;
}

void cal(Packet *SentP, const char *pch, char op = 0)
{
    char a[50] = {0}, b[50] = {0}, tmp[100], bit;
    int count = 0, operend = 0, after_op = 0, flag = 1;
    float afloat, bfloat, ans;
    memset(tmp, '\0', 100);
    sprintf(tmp, "%s", pch);
    if (!op) // sqrt
    {
        sscanf(tmp, "%f", &afloat);
        sprintf(SentP->data, "%.5f", sqrt(afloat));
        return;
    }
    while (tmp[count] != '\0')
    {
        if (tmp[count] == op && count != 0 && count != after_op)
        {
            after_op = ++count;
            flag = 0;
            operend = 0;
            continue;
        }
        if (flag)
            a[operend++] = tmp[count++];
        else
            b[operend++] = tmp[count++];
    }
    sscanf(a, "%f", &afloat);
    sscanf(b, "%f", &bfloat);
    
    
    if ( op == '+')
    	ans = afloat + bfloat;
    else if( op == '-')
    	ans = afloat - bfloat;
    else if ( op == 'x')
    	ans = afloat * bfloat;
    else if ( op == '/')
    	ans = afloat / bfloat;
    else if ( op == '^')
    	ans = pow(afloat, bfloat);
    	
 
    if (flag)
        sprintf(SentP->data, "%s", "error.");
    else
        sprintf(SentP->data, "%.5f", ans);
}







int main(void)
{
    char ServerPort[5] = "4950"; 
    int addflag , bindflag;
    int rv;
    int recvbytes;
    struct addrinfo hints, *servinfo, *p;
    char s[INET6_ADDRSTRLEN];
    default_random_engine generator;
    bernoulli_distribution distribution(Loss);

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM; 
    hints.ai_flags = AI_PASSIVE;    
    
    addflag = getaddrinfo(NULL, ServerPort, &hints, &servinfo);
    sockfd = socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol);
    bindflag = bind(sockfd, servinfo->ai_addr, servinfo->ai_addrlen);
    if (addflag != 0 && sockfd == -1 )
    {
        printf("Error.\n");
        exit(1);
    }

    if (bindflag == -1)
    {
        close(sockfd);
        printf("Server bind error.\n");
        exit(1);
    }
    freeaddrinfo(servinfo);

    printf("===Loading===\n");
    their_addr_len = sizeof their_addr;

    while (1)
    {
        Packet FirstP;
        // 3 way handshake 
        
        if ((recvbytes = recvfrom(sockfd, (char *)&FirstP, sizeof(FirstP), 0, (struct sockaddr *)&their_addr, &their_addr_len)) == -1)
        {
            perror("Receive error.\n");
            continue;
        }

        // creat a port for client
        int tmp = atoi(ServerPort);
        sprintf(ServerPort, "%d", tmp + 1);

        // let child process handle client
        int pid = fork();

        if (!pid)
        {
          
            printf("\tReceive a packet (SYN)\n");
            srand(time(NULL) + 5 * getpid());
            int SEQ = rand() % 10000 + 1;
            int ACK;
            int ssthresh = 8, MSS = 1, wnd = 1, state = slow_start, pre_state = slow_start; 
            ACK = ++FirstP.seq_num;
            reset(&FirstP);
            FirstP.SYN = 1;
            FirstP.seq_num = SEQ;
            FirstP.ack_num = ACK;
            strncpy(FirstP.data, ServerPort, sizeof(FirstP.data));
            sendto(sockfd, (char *)&FirstP, sizeof(FirstP), 0, (struct sockaddr *)&their_addr, their_addr_len);
            // 3 way handshake finish

	     addflag = getaddrinfo(NULL, ServerPort, &hints, &servinfo);
	     sockfd = socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol);
            if (addflag != 0 && sockfd == -1 )
            {
                printf("Connet  error.\n");
                exit(1);
            }


            if (bind(sockfd, servinfo->ai_addr, servinfo->ai_addrlen) == -1)
            {
                close(sockfd);
                printf("Connet bind error.\n");
                exit(1);
            }

            recvbytes = recvfrom(sockfd, (char *)&FirstP, sizeof(FirstP), 0, (struct sockaddr *)&their_addr, &their_addr_len);
            printf("\tReceive a packet ( seq_num = %u, ack_num = %u )\n", FirstP.seq_num, FirstP.ack_num);

            int num = 0;
            sscanf(FirstP.data, "%d", &num); 

            thread receiving(receive);
            char *pch = strtok(FirstP.data, " ");
            for (int i = 1; i <= num; i++)
            {
                Packet SentP;
                char *flag, *option;
                pch = strtok(NULL, " ");
                flag = pch;
                
                
               
                
                
                if (flag[1] == 'v') 
                {

                    char file_name[100] = {0};
                    pch = strtok(NULL, " ");
                    sprintf(file_name, "%s", pch);
                    int fd = open(file_name, O_RDONLY), count = 0;
                    if (fd == -1)
                    {
                        printf("File %s didn't exist.\n", file_name);
                        strcpy(SentP.data, "File didn't exist.");
                        SentP.window_size = 1;
                        SentP.ack_num = ++ACK;
                        SentP.seq_num = ++SEQ;
                        SentP.FIN = 1;
                        sendto(sockfd, (char *)&SentP, sizeof(SentP), 0, (struct sockaddr *)&their_addr, their_addr_len);
                        goto done;
                    }
                    wnd = 1;
                    printf("Sending %s\n", file_name);
                    
                    if( state == slow_start)
                    	printf("\033[34m******Slow start******\033[m\n");
                    else if(state == congestion_avoidance)
                    	printf("\033[34m******Congestion avoidance******\033[m\n");
                    else if( state == fast_recovery)
                    	printf("\033[34m******Fast recovery******\033[m\n");
                    
                    
                    while (1)
                    {

                        char tmp[1024];
                        for (int i = 0; i < wnd; i++)
                        {

                            long int rv = read(fd, Sbuff[Stail].data, 1024);
                            Sbuff[Stail].data_size = rv;

                            Sbuff[Stail].Dest = 0;
                            Sbuff[Stail].Source = 0;
                            Sbuff[Stail].seq_num = ++SEQ;
                            Sbuff[Stail].ack_num = 0;
                            Sbuff[Stail].check_sum = 0;
                            Sbuff[Stail].END = 0;
                            Sbuff[Stail].ACK = 0;
                            Sbuff[Stail].SYN = 0;
                            Sbuff[Stail].FIN = 0;
                            Sbuff[Stail].window_size = wnd;

                            Sbuff_seat[Stail] = 1;
                            if (!i)
                                Shead[1] = SEQ;

                            if (rv < 1024)
                            {
                                
                                Sbuff[Stail].FIN = 1;
                                Stail = (Stail + 1) % 512;
                                break;
                            }
                            Stail = (Stail + 1) % 512;
                        }

                        bool finish = 0;
                        int ptr = Shead[0], finish_detected, dupli = 0;
                        char s[INET6_ADDRSTRLEN];
                        inet_ntop(their_addr.ss_family, &(((struct sockaddr_in *)&their_addr)->sin_addr), s, sizeof(s));
                        printf("cwnd = %d, ssthresh = %d\n", wnd, ssthresh);
                        for (int i = 0; i < wnd; i++)
                        {
                            Sbuff[ptr].ack_num = ++ACK;
                            printf("Send a packet at 1024 byte( seq_num = %u, ack_num = %u )\n", Sbuff[ptr].seq_num, Sbuff[ptr].ack_num);
                            finish = Sbuff[ptr].FIN;
                            finish_detected = ptr;

                            if (((wnd == 4 && i == wnd - 1) && (count % 3 == 0)) || (wnd == 64 && i == wnd - 1))
                            {
                                Sbuff[ptr].ACK = 1;
                                count++;
                            }
                            else if ((wnd == 4 && i == wnd - 1) && (count % 3 == 1))
                            {
                                Sbuff[ptr].ACK = 2;
                                count++;
                            }
                            sendto(sockfd, (char *)&Sbuff[ptr], sizeof(Sbuff[ptr]), 0, (struct sockaddr *)&their_addr, their_addr_len);
                            if (finish)
                                break;
                            ptr = (ptr + 1) % 512;
                            usleep(3);
                        }

                        for (int i = 0; i < wnd; i++)
                        {
                            // Handle Synchronized
                            while (Rbuff_seat[Rhead] == 0)
                                ;

                            usleep(3);
                            if (Rbuff[Rhead].ACK)
                            {
                                printf("Receive three duplicate ACKs\n");
                                printf("\033[34m******Fast recovery******\033[m\n");
                                if (Rbuff[Rhead].ACK == 1)
                                {
                                    printf("\033[34m******Slow start******\033[m\n");
                                    ssthresh = wnd / 2;
                                    wnd = 1;
                                    dupli = 1;
                                    state = slow_start;
                                }
                                else if (Rbuff[Rhead].ACK == 2)
                                {
                                    printf("\033[34m******Congestion avoidance******\033[m\n");
                                    wnd = ssthresh;
                                    dupli = 1;
                                    state = congestion_avoidance;
                                };
                            }
                            else
                            {
                                printf("\tReceive a packet ( seq_num = %u, ack_num = %u )\n", Rbuff[Rhead].seq_num, Rbuff[Rhead].ack_num);
                            }
                            Rbuff_seat[Rhead] = 0;
                            Sbuff_seat[((Rbuff[Rhead].ack_num - 1) - Shead[1]) % 512] = 3;
                            Rhead = (Rhead + 1) % 512;
                            int tmp = Shead[0];
                            Shead[0] = (Shead[0] + 1) % 512;
                            M.unlock();

                            if (finish_detected == tmp && Sbuff[finish_detected].FIN)
                            {
                                reset_buff(finish_detected);
                                goto done;
                            }
                        }

                        if (!dupli)
                            switch (state)
                            {
                            case slow_start:
                                if (wnd >= ssthresh)
                                {
                                    printf("\033[34m******Congestion avoidance******\033[m\n");
                                    wnd = wnd + 1;
                                    state = congestion_avoidance;
                                }
                                else
                                    wnd = wnd * 2;
                                break;
                            case congestion_avoidance:
                                wnd = wnd + 1;
                                break;
                            }
                    }
                done:;
                    close(fd);
                }
                else if (flag[1] == 'D' && flag[2] == 'N' && flag[3] == 'S') // e.g. -DNS google.com
                {
                  //  printf("==Start finding: google.com to %s :\n", s);
                    pch = strtok(NULL, " ");
                    char b[INET6_ADDRSTRLEN];
                    strcpy(SentP.data, DNS(pch, b));
                    
                    SentP.seq_num = ++SEQ;
                    SentP.ack_num = ++ACK;
                    sendto(sockfd, (char *)&SentP, sizeof(SentP), 0, (struct sockaddr *)&their_addr, their_addr_len);
                    char s[INET6_ADDRSTRLEN];
                    inet_ntop(their_addr.ss_family, &(((struct sockaddr_in *)&their_addr)->sin_addr), s, sizeof(s));
                    printf("==Start finding: google.com to %s : %s \n", s , ServerPort);
                    printf("Send a packet to %s : \n", s);

                    // Handle Synchronized
                    while (Rbuff_seat[Rhead] == 0)
                        ;

                    // Prevent race conditions
                    M.lock();
                    printf("\tReceive a packet ( seq_num = %u, ack_num = %u )\n", Rbuff[Rhead].seq_num, Rbuff[Rhead].ack_num);
                    Rbuff_seat[Rhead] = 0;
                    Rhead = (Rhead + 1) % 512;
                    M.unlock();
                    printf("==Finishing finding==\n");
                }
                else
                {
                    pch = strtok(NULL, " ");

                    if (flag[1] == 'a' && flag[2] == 'd' ) 
                        cal(&SentP, pch, '+');

                    else if (flag[1] == 's' && flag[2] == 'u' ) 
                        cal(&SentP, pch, '-');

                    else if (flag[1] == 'm' && flag[2] == 'u' ) 
                        cal(&SentP, pch, 'x');

                    else if (flag[1] == 'd' && flag[2] == 'i' ) 
                        cal(&SentP, pch, '/');

                    else if (flag[1] == 'p' && flag[2] == 'o' ) 
                        cal(&SentP, pch, '^');

                    else if (flag[1] == 's' && flag[2] == 'q' ) 
                        cal(&SentP, pch, 0);
                    else // error
                    {
                        printf("Invaild flag.\n");
                        continue;
                    }
                    SentP.seq_num = ++SEQ;
                    SentP.ack_num = ++ACK;
                    sendto(sockfd, (char *)&SentP, sizeof(SentP), 0, (struct sockaddr *)&their_addr, their_addr_len);
                    char s[INET6_ADDRSTRLEN];
                    inet_ntop(their_addr.ss_family, &(((struct sockaddr_in *)&their_addr)->sin_addr), s, sizeof(s));
                    printf("Send a packet to %s : \n", s);

                    while (Rbuff_seat[Rhead] == 0)
                        ;
                    M.lock();
                    printf("\tReceive a packet ( seq_num = %u, ack_num = %u )\n", Rbuff[Rhead].seq_num, Rbuff[Rhead].ack_num);
                    Rbuff_seat[Rhead] = 0;
                    Rhead = (Rhead + 1) % 512;
                    M.unlock();
                }
            }
            receiving.join();
            printf("Finish\n");
            close(sockfd);
            exit(0);
        }
    }

    return 0;
}


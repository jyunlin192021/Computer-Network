#include <iostream>
#include <fstream>
#include <string>
#include <thread>
#include <mutex>
#include <queue>
#include <unistd.h>
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
//接收緩衝區
int Rhead = 0, Rtail = 0;
int Rbuff_seat[512] = {0}; //用於檢查接收緩衝區中每個位置的狀態
Packet Rbuff[512];
//addrss and socket
struct sockaddr_storage their_addr;
socklen_t their_addr_len;
int sockfd;


void receive()
{
    while (1)
    {
        Packet rPacket;
        recvfrom(sockfd, (char *)&rPacket, sizeof(rPacket), 0, (struct sockaddr *)&their_addr, &their_addr_len);
        if (rPacket.END)
        {
            close(sockfd);
            break;
        }else{
       	 M.lock();
        	 Rbuff_seat[Rtail] = 1;
       	 Rbuff[Rtail].Dest = rPacket.Dest;
       	 Rbuff[Rtail].Source = rPacket.Source;
      		 Rbuff[Rtail].seq_num = rPacket.seq_num;
      	  	 Rbuff[Rtail].ack_num = rPacket.ack_num;
        	 Rbuff[Rtail].check_sum = rPacket.check_sum;
        	 Rbuff[Rtail].data_size = rPacket.data_size;
        	 Rbuff[Rtail].END = rPacket.END;
        	 Rbuff[Rtail].ACK = rPacket.ACK;
        	 Rbuff[Rtail].SYN = rPacket.SYN;
        	 Rbuff[Rtail].FIN = rPacket.FIN;
        	 Rbuff[Rtail].window_size = rPacket.window_size;
        	 for (int i = 0; i < 1024; i++)
            		Rbuff[Rtail].data[i] = rPacket.data[i];
        	 Rtail = (Rtail + 1) % 512;
        	 M.unlock();
        }
    }
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


int main(int argc, char *argv[])
{
    srand(time(NULL) + 5 * getpid());
    char ServerPort[5] = "4950";
    char ServerPort_[5] = "4950"; 
    int SEQ = rand() % 10000 + 1; 
    int addflag, ACK;  
    int sendbytes,recvbytes;    
    struct addrinfo hints, *servinfo;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    
    addflag = getaddrinfo(argv[1], ServerPort, &hints, &servinfo);
    sockfd = socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol);
    
    if (addflag != 0 || sockfd == -1)
    {
        printf("ERROR!\n");
        exit(1);
    }
   
    freeaddrinfo(servinfo);

    //3-way handshake START
    printf("Server's IP address : %s\n" , argv[1]);
    printf("Server's port: %s\n",ServerPort);
    printf("=====Start the three-way handshake======\n");
    printf("Send a package(SYN) to %s : %s\n", argv[1], ServerPort);
    Packet FirstP;
    FirstP.SYN = 1;
    FirstP.seq_num = SEQ;
    
    sendbytes = sendto(sockfd, (char *)&FirstP, sizeof(FirstP), 0, servinfo->ai_addr, servinfo->ai_addrlen);
    if (sendbytes == -1)
    {
        printf("3-Way-Handshake ERROR\n");
        exit(1);
    }
    else
    {
        reset(&FirstP);
        recvbytes = recvfrom(sockfd, (char *)&FirstP, sizeof(FirstP), 0, (struct sockaddr *)&their_addr, &their_addr_len);
        printf("Receive package(SYN/ACK) from %s : %s\n", argv[1], ServerPort);
        printf("\tReceive a package ( seq_num = %u, ack_num = %u )\n", FirstP.seq_num, FirstP.ack_num);
        ACK = FirstP.seq_num + 1;
	FirstP.seq_num = FirstP.seq_num + 1;
        strncpy(ServerPort, FirstP.data, sizeof(ServerPort) - 1);
        getaddrinfo(argv[1], ServerPort, &hints, &servinfo);
        sockfd = socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol);

        //sent request
        reset(&FirstP);
        char num[50] = {0};
        int value = (argc - 2) / 2;
        sprintf(num, "%d", value); //caculate request num
        strcat(FirstP.data, num);        //request num
        
        for (int i = 2; i < argc; i++)
        {
            strcat(FirstP.data, " ");
            strcat(FirstP.data, argv[i]);
        }

        
        FirstP.seq_num = ++SEQ;
        FirstP.ack_num = ACK;
        sendto(sockfd, (char *)&FirstP, sizeof(FirstP), 0, servinfo->ai_addr, servinfo->ai_addrlen);
        reset(&FirstP);

        printf("Send a package(ACK) to %s : %s\n", argv[1], ServerPort_);
        printf("====Complete the three-way handshake====\n");
    }
    //3-way handshake END

    
    
    thread receiving(receive); //handle receiving
	int flag = 0;
    for (int i = 1; i <= (argc - 2) / 2; i++)
    {
        char a[5] = {0}, add[500] = {0}, s[INET6_ADDRSTRLEN];
        strcat(a, argv[i * 2]);
        strcat(add, argv[i * 2 + 1]);
        Packet SentP;
	int cond;
	if ( a[i] == 'v' )
		cond = 1;
	else if ( a[1] == 'D' && a[2] == 'N' && a[3] == 'S' )
		cond = 2;
	else if ( a[1] == 'a' && a[2] == 'd')
		cond = 3;
	else if (a[1] == 's' && a[2] == 'u' )
		cond = 3;
	else if ( a[1] == 'm' && a[2] == 'u' )
		cond = 3;
	else if ( a[1] == 'd' && a[2] == 'i' )
		cond = 3;
	else if ( a[1] == 'p' && a[2] == 'o' )
		cond = 3;
	else if ( a[1] == 's' && a[2] == 'q' )
		cond = 3;
	else
		cond = 4;


	int fd,tmp;
	char file_name[20] = {0}, tmp_pid[10] = {0};
	switch (cond){
		case 1:
			printf("\nReceiving %s form %s : %s\n", add, argv[1], ServerPort_);
            //創建一個用於保存接收數據的文件
            file_name[20] = {0}, tmp_pid[10] = {0};
            sprintf(tmp_pid, "%d", getpid());
            strcpy(file_name, "received");
            strcat(file_name, tmp_pid);
            strcat(file_name, add);
            fd = open(file_name, O_WRONLY | O_CREAT | O_TRUNC, S_IRWXU);
            tmp = -1;
            while (1)
            {
                while (Rbuff_seat[Rhead] == 0);

                M.lock();
                if (Rbuff[Rhead].ACK) //序號為1且沒有相應的封包時，判斷該封包丟失
                {
                    SentP.ACK = Rbuff[Rhead].ACK;
                    if (Rbuff[Rhead].ACK == 1)
                        printf("\n\nPacket loss ( seq_num = %u, ack_num = %u )\n\n", Rbuff[Rhead].seq_num, Rbuff[Rhead].ack_num);
                }
                if (tmp != Rbuff[Rhead].window_size) //檢查window_size
                {
                    printf("Receive %d packet from %s : %s\n", Rbuff[Rhead].window_size, argv[1], ServerPort_);
                    printf("\tReceive a packet ( seq_num = %u, ack_num = %u )\n", Rbuff[Rhead].seq_num, Rbuff[Rhead].ack_num);
                }
                if (Rbuff[Rhead].FIN && !strcmp(Rbuff[Rhead].data, "File didn't exist."))
                {
                    printf("\tFile %s didn't exist.\n", add);
                    Rbuff_seat[Rhead] = 0;
                    Rhead = (Rhead + 1) % 512;
                    break;
                }
                tmp = Rbuff[Rhead].window_size;
                ACK = Rbuff[Rhead].seq_num;

                write(fd, Rbuff[Rhead].data, Rbuff[Rhead].data_size);

                int finish = Rbuff[Rhead].data_size;
                Rbuff_seat[Rhead] = 0;
                Rhead = (Rhead + 1) % 512;
                M.unlock();

                SentP.seq_num = ++SEQ;
                SentP.ack_num = ++ACK;
                sendto(sockfd, (char *)&SentP, sizeof(SentP), 0, servinfo->ai_addr, servinfo->ai_addrlen);
                reset(&SentP);
                if (finish < 1024) //封包大小小於1024(finally)
                    break;
                usleep(3);
            }
            close(fd);
            	break;
            case 2:
            	while (Rbuff_seat[Rhead] == 0);
            M.lock();
            printf("\nFinding IP address of google.com by %s : %s\n", argv[1], ServerPort_);
            printf("\tReceive a packet ( seq_num = %u, ack_num = %u )\n", Rbuff[Rhead].seq_num, Rbuff[Rhead].ack_num);
            printf("Result : %s\n", Rbuff[Rhead].data);
            printf("Send a packet(ACK) to %s : %s\n", argv[1], ServerPort_);
            ACK = Rbuff[Rhead].seq_num; //接收到的packet的seq store在ACK中
            Rbuff_seat[Rhead] = 0; //該位置之前的數據已經被處理，可以重新使用
            Rhead = (Rhead + 1) % 512; //更新接收緩衝區的前緣指標
            M.unlock();   
            SentP.seq_num = ++SEQ; //更新發送封包的序號
            SentP.ack_num = ++ACK; //更新發送封包的確認序號
            sendto(sockfd, (char *)&SentP, sizeof(SentP), 0, servinfo->ai_addr, servinfo->ai_addrlen); //封包發送到指定的目的地
            printf("Finishing finding\ngoogle.com\n\n");
            break;
            case 3:
            	while (Rbuff_seat[Rhead] == 0); 
            M.lock();
            printf("Receive a calculation result from %s : %s\n", argv[1], ServerPort_);
            printf("\tReceive a packet ( seq_num = %u, ack_num = %u )\n", Rbuff[Rhead].seq_num, Rbuff[Rhead].ack_num);
            if (a[1] == 's' && a[2] == 'q')
                printf("\tresult: %s^(1/2) = %s\n", add, Rbuff[Rhead].data);
            else
                printf("\tresult: %s = %s\n", add, Rbuff[Rhead].data);
            ACK = Rbuff[Rhead].seq_num; //接收到的packet的seq store在ACK中
            Rbuff_seat[Rhead] = 0; //該位置之前的數據已經被處理，可以重新使用
            Rhead = (Rhead + 1) % 512; //更新接收緩衝區的前緣指標
            M.unlock();
            SentP.seq_num = ++SEQ; //更新發送封包的序號
            SentP.ack_num = ++ACK; //更新發送封包的確認序號
            sendto(sockfd, (char *)&SentP, sizeof(SentP), 0, servinfo->ai_addr, servinfo->ai_addrlen); ////封包發送到指定的目的地
            break;
            default:
            	printf("Invaild flag.\n");
            	flag = 1;
            	break;
            
            if( flag ==1 )
            	continue;


    }
}
   
    Packet FinalP;
    FinalP.END = 1;
    sendto(sockfd, (char *)&FinalP, sizeof(FinalP), 0, servinfo->ai_addr, servinfo->ai_addrlen);
    receiving.join();
  
    return 0;
}



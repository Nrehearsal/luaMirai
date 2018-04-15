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

#define ROUTER_ADDR "117.36.153.180"
#define SERVER_ADDR "192.168.1.142"

int cfd, try_times;
struct sockaddr_in serv_addr;
status conn_status = SOCKET_CLOSED;
uint8_t databuf[512];
int start_time;
int time_flag;
int data_len;

static void establish_connection();
static void close_connection();
static int negotiate(uint8_t *buf, int length);
static BOOL can_get_data(uint8_t *source, int data_len, int8_t *current_pos, int amount);
static int can_send_username(uint8_t *data, int data_len);
static int can_send_password(uint8_t *data, int data_len);
static int str_find(uint8_t* source, int data_len, char* target);
static int can_send_sh_cmd(uint8_t *data, int data_len);
static int is_exec_sh_success(uint8_t *data, int data_len);

/*int main(void)
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
  }*/

int main(void)
{
	int data_len;
	int nfds;
	fd_set fdread, fdwrite;
	int maxfd;
	struct timeval timeout;
	timeout.tv_sec = 1;
	timeout.tv_usec = 0;

	establish_connection();
	maxfd = cfd;

	while(1)
	{
		int ret;
		FD_ZERO(&fdread);
		FD_ZERO(&fdwrite);

		int max_timeout;
		max_timeout = (conn_status > SOCKET_CONNECTING ? 30 : 5);

		//load fd into fd_set
		if (conn_status >= SOCKET_CONNECTING && time_flag - start_time > max_timeout)
		{
			if (conn_status > TELNET_HANDLE_IAC && try_times++ < 10)		
			{
				establish_connection();	
			}
			else
			{
				close_connection();	
				break;
			}
		}

		if (conn_status == SOCKET_CONNECTING)
		{
			FD_SET(cfd, &fdwrite);
		}

		if (conn_status != SOCKET_CLOSED)
		{
			FD_SET(cfd, &fdread);
		}

		nfds = select(maxfd+1, &fdread, &fdwrite, NULL, &timeout);

		if (nfds == -1)
		{
			perror("select:");	
		}
		time_flag = time(NULL);

		if (FD_ISSET(cfd, &fdwrite))
		{
			int err = 0;
			socklen_t err_len = sizeof(err);
			ret = getsockopt(cfd, SOL_SOCKET, SO_ERROR, &err, &err_len);
			if (err == 0 &&	ret == 0)
			{
				conn_status = TELNET_HANDLE_IAC;
				/*next combination*/
			}
			else
			{
				close_connection();
				continue;
			}
		}

		if (FD_ISSET(cfd, &fdread))
		{
			int ret;
			data_len = recv(cfd, databuf, sizeof(databuf), MSG_NOSIGNAL);
			assert(data_len);
			start_time = time(NULL);

			if (databuf[0] == IAC && conn_status == TELNET_SEND_USERNAME)
			{
				conn_status = TELNET_HANDLE_IAC;	
			}

			while(1)
			{
				int used = 0;
				int ret = 0;

				switch (conn_status)
				{
					case TELNET_HANDLE_IAC:
						used = negotiate(databuf, data_len);
						if (used > 0)
						{
							conn_status = TELNET_SEND_USERNAME;	
						}
						break;
					case TELNET_SEND_USERNAME:
						/*confirm whether the uesrname can be sent*/
						used = can_send_username(databuf, data_len);
						if (used > 0)
						{
#ifdef ROUTER
							ret = send(cfd, "ZXR10", 5, MSG_NOSIGNAL);
#else
							ret = send(cfd, "ubuntu", 6, MSG_NOSIGNAL);
#endif
							ret = send(cfd, "\r\n", 2, MSG_NOSIGNAL);
							assert(ret);
							conn_status = TELNET_SEND_PASSWORD;
#ifdef ROUTER
							printf("USERNAME SEND: ZXR10 %d\n", used);
#else
							printf("USERNAME SEND: ubuntu %d\n", used);
#endif
						}
						break;
					case TELNET_SEND_PASSWORD:
						/*confirm whether the password can be sent*/
						used = can_send_password(databuf, data_len);
						if (used > 0)
						{
#ifdef ROUTER
							ret = send(cfd, "zsr", 3, MSG_NOSIGNAL);
#else
							//ret = send(cfd, "Wind142.", 8, MSG_NOSIGNAL);
							ret = send(cfd, "Wind142.", 8, MSG_NOSIGNAL);
#endif
							ret = send(cfd, "\r\n", 2, MSG_NOSIGNAL);
							assert(ret);

							conn_status = TELNET_VERIFY_PASS;	
#ifdef ROUTER
							printf("PASSWORD SEND: zsr %d\n", used);
#else
							printf("PASSWORD SEND: Wind142. %d\n", used);
#endif
						}
						break;
					case TELNET_VERIFY_PASS:
						/*is the login successfull?*/
						used = can_send_sh_cmd(databuf, data_len);
						if (used > 0)
						{
							ret = send(cfd, "sh", 2, MSG_NOSIGNAL);
							assert(ret);
							ret = send(cfd, "\r\n", 2, MSG_NOSIGNAL);
							assert(ret);

							printf("SH CMD SEND: sh %d\n", used);

							conn_status = TELNET_VERIFY_SH;
							/*report result to server*/
							for (int i = 0; i < data_len; i++)
							{
								printf("%c", databuf[i]);
							}
							printf("\n");
						}
						else
						{
							try_times++;
						}
						break;
					case TELNET_VERIFY_SH:
						used = is_exec_sh_success(databuf, data_len);
						{
							if (used > 0)
							{
								conn_status = TELNET_LOGIN_SUCCESS;	
								printf("login success!\n");
								for (int i = 0; i < data_len; i++)
								{
									printf("%c", databuf[i]);
								}
								printf("\n");
							}
						}
					default:
						used = 0;
						break;
				}

				if (used < 0)
				{
					break;
				}
				else
				{
					/*move unprocessed data to the front*/	
					data_len = data_len - used;
					if (data_len >= 0)
					{
						memmove(databuf, databuf+ret, data_len);
					}
					else
					{
						break;	
					}
				}
			}
		}
		if (conn_status == TELNET_LOGIN_SUCCESS)
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

static int is_exec_sh_success(uint8_t *data, int data_len)
{
	char* data_ptr = (char*)data;
	int handle_len = -1;
	int i;
	int ret;
	printf("%s\n", data_ptr);

	for (i = data_len; i > 0; i--)
	{
		if (data_ptr[i] == '$' || data_ptr[i] == '#' || data_ptr[i] == '%' || data_ptr[i] == '~' || data_ptr[i] == '>')
		{
			handle_len = i;
			break;
		}
	}

	if (handle_len == 0)
	{
		ret = str_find(data, data_len, "sh");	
		if (ret > 0)
		{
			handle_len = ret;	
		}
	}

	return handle_len;
}

static int can_send_sh_cmd(uint8_t *data, int data_len)
{
	char* data_ptr = (char*)data;
	int handle_len = -1;
	int i;
	int ret;

	for (i = data_len; i > 0; i--)
	{
		if (data_ptr[i] == '#' || data_ptr[i] == '$' || data_ptr[i] == '~' || data_ptr[i] == '>' || data_ptr[i] == '%')
		{
			handle_len = i;
			break;
		}
	}
	if (handle_len == 0)
	{
		ret = str_find(data, data_len, "ZXR10");	
		if (ret > 0)
		{
			handle_len = ret;	
		}
	}

	return handle_len;
}

static int can_send_username(uint8_t *data, int data_len)
{
	char *data_ptr = (char*)data;	
	int handle_len = 0;
	int i;
	int ret;

	for (i = data_len; i > 0; i--)
	{
		if (data_ptr[i] == ':' || data_ptr[i] == '>' || data_ptr[i] == '%' || data_ptr[i] == '#' || data_ptr[i] == '$')
		{
			handle_len = i;
			printf("Find: username at %d\n", i);
			break;
		}
		else
		{
			handle_len = 0;	
		}
	}

	if (handle_len == 0)
	{
		ret = str_find(data, data_len, "login");	
		if (ret == -1)
		{
			ret = str_find(data, data_len, "enter");
		}
		handle_len = ret;
	}

	return handle_len;
}

static int can_send_password(uint8_t *data, int data_len)
{
	char *data_ptr = (char*)data;
	int handle_len = 0;
	int ret;
	int i;

	for (i = data_len; i > 0; i--)
	{
		if (data_ptr[i] == ':' || data_ptr[i] == '>' || data_ptr[i] == '%' || data_ptr[i] == '#' || data_ptr[i] == '$')
		{
			handle_len = i;	
			printf("Find: password at %d\n", i);
			break;
		}
		else
		{
			handle_len = 0;	
		}
	}

	if (handle_len == 0)
	{
		ret = str_find(data, data_len, "ssword");	
		handle_len = ret;
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

static void establish_connection()
{
	int ret;
	serv_addr.sin_family = AF_INET;
#ifdef ROUTER
	inet_aton(ROUTER_ADDR, (void*)&serv_addr.sin_addr);
#else
	inet_aton(SERVER_ADDR, (void*)&serv_addr.sin_addr);
#endif
	serv_addr.sin_port = htons(23);

	cfd = socket(AF_INET, SOCK_STREAM, 0);
	assert(cfd);
	ret = connect(cfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr));
	assert(!ret);
	conn_status = SOCKET_CONNECTING;
	start_time = time(NULL);
}

static void close_connection()
{
	if (cfd != -1)
	{
		close(cfd);	
		cfd = -1;
		conn_status = SOCKET_CLOSED;
	}
}

//sub-option negotiation
static int negotiate(uint8_t *data, int data_len)
{
	uint8_t *data_ptr = data;
	int ret;
	int handle_len = 0;

	while (handle_len < data_len)
	{
		if (data_ptr[0] != IAC)
		{
			break;	
		}

		/*to check whether it can conitune*/
		if (!can_get_data(databuf, data_len, data_ptr, 2))
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

			ret = send(cfd, iac_win_size, 3, MSG_NOSIGNAL);
			assert(ret);
			ret = send(cfd, tell_win_size, 9, MSG_NOSIGNAL);
			assert(ret);

			data_ptr += 3;
			handle_len += 3;
		}
		else
		{
			/*if (data_ptr[1] == DO)
			{
				data_ptr[1] = WONT;	
			}
			else if (data_ptr[1] == WILL)
			{
				data_ptr[1] = DO;	
			}*/
			data_ptr[1] = data_ptr[1] == DO ? WONT : DO;

			ret = send(cfd, data_ptr, 3, MSG_NOSIGNAL);
			assert(ret);

			data_ptr += 3;
			handle_len += 3;
		}
	}
	return handle_len;
}

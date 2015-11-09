#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/types.h>
#include <linux/netfilter.h>

#include "nf_proxy_tcp.h"

#define bool int
#define TRUE 1
#define FALSE 0
#define OK 1
#define BUF_SIZE 65535

#define pxy_printf(flag, format, args...) \
	((flag) ? printf(format , ## args) : 0)

#ifndef CONFIG_TPROXY
#define CONFIG_TPROXY
#endif	/* CONFIG_TPROXY */

//#ifdef CONFIG_TPROXY
#ifndef NIPQUAD
#define NIPQUAD(addr) \
	((unsigned char *)&addr)[3], \
        ((unsigned char *)&addr)[2], \
        ((unsigned char *)&addr)[1], \
        ((unsigned char *)&addr)[0]
#endif	/* NIPQUAD */
//#endif	/* CONFIG_TPROXY */

int debug = 1;

int remote_port, local_port;
int listen_fd;
char *remote_host;
struct sockaddr_in server_addr;

int create_server(int local_port);
int server_loop();
int handler_client(int connfd);
#ifdef CONFIG_TPROXY
int create_conn_server(int);
#else
int create_conn_server(int connfd, char* remote_host, int remote_port);
#endif	/* CONFIG_TPROXY */
int redirect_data(int srcfd, int dstfd);
void sigchld_handler(int signal);

int main(int argc, char *argv[]) {
	int opt;
	bool show_version_flag = FALSE;
	bool remote_host_flag = FALSE;
	bool local_port_flag = FALSE;
	bool remote_port_flag = FALSE;
	char str[100];
	struct hostent *host_s;

	/*
	 * v For version
	 * l For localhost port
	 * h For remote ip
	 * p For remote port
	 */

	while ((opt = getopt(argc, argv, "vl:h:p:")) != -1) {
		switch (opt) {
		case 'v':
			show_version_flag = TRUE;
			break;
		case 'h':
			remote_host_flag = TRUE;
			remote_host = optarg;
			break;
		case 'l':
			local_port_flag = TRUE;
			local_port = atoi(optarg);
			break;
		case 'p':
			remote_port_flag = TRUE;
			remote_port = atoi(optarg);
			break;
		default:
			break;
		}
	}

	if (show_version_flag) {
		printf("TcpProxy Version 1.1\n");
	}

	if (!(local_port_flag && remote_port_flag && remote_port_flag)) {
		printf("Usage: tcpproxy -l 8080 -h 127.0.0.1 -p 80\n");
		exit(0);
	} else {
		printf("tcpproxy -l %d -h %s -p %d\n", local_port, remote_host,
				remote_port);
	}
	signal(SIGCHLD, sigchld_handler); // prevent ended children from becoming zombies
	if (create_server(local_port) == -1) {
		printf("create server() error.Exiting...");
		exit(-1);
	}
	server_loop();
	return 0;
}
void sigchld_handler(int signal) {
	while (waitpid(-1, NULL, WNOHANG) > 0)
		;
}
int create_server(int local_port) {
	int yes = 1; 
	listen_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (listen_fd == -1) {
		printf("socket() error %d : %s\n", errno, strerror(errno));
		return -1;
	}

	setsockopt(listen_fd, SOL_SOCKET, 2, (char *) &yes, sizeof(yes)) ;
	setsockopt(listen_fd, SOL_SOCKET, 15, (char *) &yes, sizeof(yes)) ;

	server_addr.sin_port = htons(local_port);
	server_addr.sin_addr.s_addr = htonl(INADDR_ANY );
	if ((bind(listen_fd, (struct sockaddr *) &server_addr, sizeof(server_addr)))
			== -1) {
		printf("bind() error %d : %s \n", errno, strerror(errno));
		return -1;
	}
	if ((listen(listen_fd, 20)) == -1) {
		printf("listen() error %d : %s \n", errno, strerror(errno));
		return -1;
	}
	return listen_fd;
}

int server_loop() {
	int connfd;
	while (1) {
		connfd = accept(listen_fd, (struct sockaddr *) NULL, NULL );
		if (connfd == -1) {
			printf("accept() error %d : %s\n", errno, strerror(errno));
			return -1;
		}
		if (fork() == 0) {
			close(listen_fd);
			handler_client(connfd);
			exit(0);
		}
		close(connfd);
	}
	return OK;
}

int handler_client(int connfd) {
	int client_fd;
#ifdef CONFIG_TPROXY
	client_fd = create_conn_server(connfd);
#else
	client_fd = create_conn_server(connfd, remote_host, remote_port);
#endif	/* CONFIG_TPROXY */
	if (fork() == 0) {
		redirect_data(connfd, client_fd);
		exit(0);
	}
	if (fork() == 0) {
		redirect_data(client_fd, connfd);
		exit(0);
	}
	close(connfd);
	close(client_fd);
	return OK;
}

#ifdef CONFIG_TPROXY
int create_conn_server(int connfd) 
{
	int ret = 0;
	int client_fd;
	struct sockaddr_in server_addr, bind_addr;
	sk_tuple_t stream;
	int transparent = 1;
	int len = 0;

	client_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (client_fd == -1) {
		printf("socket errno %d : %s \n", errno, strerror(errno));
		return -1;
	}
	
	/* Set client_fd IP_TRANSPARENT */
	ret = setsockopt (client_fd, SOL_IP, IP_TRANSPARENT, (int *)&transparent, sizeof(int));
	if (ret < 0) {
		perror("setsockopt()");
		close(client_fd);
		return -1;
	}

	/* Get client to server tuple */
	len = sizeof(struct sk_tuple);
	ret = getsockopt(connfd, SOL_IP, SO_GET_TUPLE_BY_SK, (sk_tuple_t*)&stream, (socklen_t*)&len);
	if (ret < 0) {
		perror("getsockopt()");
		close(client_fd);
		return -1;
	}

	pxy_printf(debug, "Get tupe: [src=%u.%u.%u.%u sport=%u "
			   "dst=%u.%u.%u.%u dport=%u].\n",
			   NIPQUAD(stream.c.ip), stream.client_port,
			   NIPQUAD(stream.s.ip), stream.server_port);

	memset(&bind_addr, 0, sizeof(bind_addr));
	bind_addr.sin_family = AF_INET;
	bind_addr.sin_port   = htons(stream.client_port);
	bind_addr.sin_addr.s_addr = htonl(stream.c.ip);

	ret = bind(client_fd, (struct sockaddr*)&bind_addr, sizeof(bind_addr));
	if (0 != ret) {
		perror("bind()");
		close(client_fd);
		return -1;
	}

	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(stream.server_port);
	server_addr.sin_addr.s_addr = htonl(stream.s.ip);

	if ((connect(client_fd, (struct sockaddr *) &server_addr,
			sizeof(server_addr))) < 0) {
		printf("connect error %d : %s \n", errno, strerror(errno));
		return -1;
	}
	return client_fd;
}

#else	/* CONFIG_TPROXY */

int create_conn_server(int connfd, char* remote_addr, int remote_port) {
	int client_fd;
	int	rc;
	size_t	socksize;
	struct sockaddr_in sock;
	struct sockaddr_in client_addr;

	client_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (client_fd == -1) {
		printf("socket errno %d : %s \n", errno, strerror(errno));
		return -1;
	}


	socksize = sizeof(sock);
#define SO_ORIGINAL_DST 80
	rc = getsockopt(connfd, SOL_IP, SO_ORIGINAL_DST, &sock, &socksize);
	
	client_addr.sin_family = AF_INET;
	client_addr.sin_port = sock.sin_port;
	client_addr.sin_addr = sock.sin_addr;
	//inet_pton(AF_INET, remote_addr, &client_addr.sin_addr);


        pxy_printf(debug, "Go to dst=%u.%u.%u.%u dport=%u].\n",
                           NIPQUAD(client_addr.sin_addr.s_addr), client_addr.sin_port);

	if ((connect(client_fd, (struct sockaddr *) &client_addr,
			sizeof(client_addr))) < 0) {
		printf("connect error %d : %s \n", errno, strerror(errno));
		return -1;
	}
	return client_fd;
}
#endif	/* CONFIG_TPROXY */

int redirect_data(int srcfd, int dstfd) {
	char buf[BUF_SIZE];
	int n;
	while ((n = recv(srcfd, buf, BUF_SIZE, 0)) > 0) {
		send(dstfd, buf, n, 0);
	}
	close(srcfd);
	close(dstfd);
	return OK;
}

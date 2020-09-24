/**
 * @neelamra_assignment1
 * @author  Srisai Karthik Neelamraju <neelamra@buffalo.edu>
 * @version 1.0
 *
 * @section LICENSE
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details at
 * http://www.gnu.org/copyleft/gpl.html
 *
 * @section DESCRIPTION
 *
 * This contains the main function of Text Chat Application with one server
 * and at most four clients connected to the server through TCP connections.
 * A client can send messages to and receive messages from fellow clients.
 * All the messages pass through the server, which uses select() system call
 * for handling multiplexing between different socket descriptors. The clients
 * have option to execute several commands like send, broadcast and block once
 * they log in to the chat application.
 * 
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>

#include "../include/global.h"
#include "../include/logger.h"

#define TRUE 1
#define FALSE 0
#define STDIN 0
#define BACKLOG 5
#define IP_SIZE 16
#define CMD_SIZE 30
#define MSG_SIZE 256
#define PORT_SIZE 10
#define MAX_CMD_LEN 3
#define MAX_CLIENTS 4
#define HOSTNAME_SIZE 40
#define BUFFER_SIZE 256
#define MAX_BUFF_MSG 100
#define MAX_FILE_SIZE 10000000

struct client{
	char hostname[HOSTNAME_SIZE];
	char ip_addr[IP_SIZE];
	int num_msg_sent;
	int num_msg_recv;
	int listen_port;
	int logged_in;
	char blocked[MAX_CLIENTS][IP_SIZE];
	int fd;
	int n_blocked;
	int n_buffered;
	int exited;
	int listen_fd;
	int stat;
};

struct buff_msg{
	char send_ip[IP_SIZE];
	char recv_ip[IP_SIZE];
	char msg[MSG_SIZE];
	int sent;
};

struct client clients[MAX_CLIENTS];
struct buff_msg buffered[MAX_BUFF_MSG];
char file_buf[MAX_FILE_SIZE + BUFFER_SIZE];

void server(char *port);
void client(char *port);
void get_ipaddr();
int comparator(const void *c1, const void *c2);
int isValidIP(char *ip_addr);
int isValidDigit(char *str);
int sendall(int s, char *buf, int *len);
int recvall(int s, char *buf, int *len);


/**
 * function for server-side implementation, based on recitation file server.c
 *
 * @param  port Listening port number
 */
void server(char *port)
{
	int server_socket, head_socket, selret, sock_index, fdaccept=0, caddr_len, n_reg=0, n_online=0, loc=0, n_buff=0;
	struct sockaddr_in cl_addr;
	struct addrinfo hints, *res;
	fd_set master_list, watch_list;

	/* setting up hints structure */
	memset(&hints, '\0', sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	/* filling up address structures */
	if (getaddrinfo(NULL, port, &hints, &res) != 0){
		perror("SERVER: Method getaddrinfo() failed");
	}

	/* creating a socket */
	server_socket = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (server_socket < 0){
		perror("SERVER: Failed to create socket");
	}

	/* associating the socket with a port */
	if (bind(server_socket, res->ai_addr, res->ai_addrlen) < 0 ){
		perror("SERVER: Bind failed");
	}

	freeaddrinfo(res);

	/* listening on the socket */
	if (listen(server_socket, BACKLOG) < 0){
		perror("SERVER: Unable to listen on port");
	}

	/* zero selecting the FD sets */
	FD_ZERO(&master_list);
	FD_ZERO(&watch_list);

	/* registering the server listening socket */
	FD_SET(server_socket, &master_list);

	/* registering STDIN to process commands from the shell */
	FD_SET(STDIN, &master_list);

	head_socket = server_socket;

	while (TRUE){

		memcpy(&watch_list, &master_list, sizeof(master_list));

		printf("\n[PA1-Server@CSE589]$ ");
		fflush(stdout);

		/* multiplexing using select() system call */
		selret = select(head_socket + 1, &watch_list, NULL, NULL, NULL);
		if (selret < 0){
			perror("SERVER: Select failed");
		}

		/* checking if we have any sockets/STDIN to process */
		if (selret > 0){

			/* looping through all socket descriptors to check which ones are ready */
			for (sock_index = 0; sock_index <= head_socket; sock_index++){

				if (FD_ISSET(sock_index, &watch_list)){

					/* checking for any new commands on STDIN */
					if (sock_index == STDIN){

						/* getting commands from the shell */
						char inp[CMD_SIZE];
						if (fgets(inp, CMD_SIZE-1, stdin) == NULL){
							exit(-1);
						}
						if (!strcmp(inp, "\n")){
							continue;
						}

						/* tokenizing the input, code from rec2.pdf page 4 */
						int argc = 0;
						char *arg = strtok(inp, "\n");
						arg = strtok(arg, " ");
						char *cmd[MAX_CMD_LEN];
						memset(cmd, '\0', sizeof(cmd));
						while (arg){
							cmd[argc] = arg;
							argc += 1;
							arg = strtok(NULL, " ");
						}

						/* AUTHOR command */
						if (!strcmp(cmd[0], "AUTHOR")){
							cse4589_print_and_log("[%s:SUCCESS]\n", "AUTHOR");
							cse4589_print_and_log("I, %s, have read and understood the course academic integrity policy.\n", "neelamra");
							cse4589_print_and_log("[%s:END]\n", "AUTHOR");
						}

						/* IP command */
						else if (!strcmp(cmd[0], "IP")){
							get_ipaddr();
						}

						/* PORT command */
						else if (!strcmp(cmd[0], "PORT")){
							cse4589_print_and_log("[%s:SUCCESS]\n", "PORT");
							cse4589_print_and_log("PORT:%d\n", atoi(port));
							cse4589_print_and_log("[%s:END]\n", "PORT");
						}

						/* LIST command */
						else if (!strcmp(cmd[0], "LIST")){
							int i, n = 0;
							qsort(clients, n_reg, sizeof(struct client), comparator);
							cse4589_print_and_log("[%s:SUCCESS]\n", "LIST");
							for (i = 0; i < n_reg; i++){
								if (!clients[i].logged_in || clients[i].exited){
									continue;
								}
								cse4589_print_and_log("%-5d%-35s%-20s%-8d\n", ++n, clients[i].hostname, clients[i].ip_addr, clients[i].listen_port);
							}
							cse4589_print_and_log("[%s:END]\n", "LIST");
						}

						/* BLOCKED command */
						else if (!strcmp(cmd[0], "BLOCKED")){
							char blk_ip[IP_SIZE];
							strcpy(blk_ip, cmd[1]);

							/* checking if the input IP address is valid */
							if (!isValidIP(cmd[1])){
								cse4589_print_and_log("[%s:ERROR]\n", "BLOCKED");
								cse4589_print_and_log("[%s:END]\n", "BLOCKED");
								continue;
							}

							/* checking if there is indeed a client with this IP */
							int i, flag = FALSE;
							for (i = 0; i < n_reg; i++){
								if (!strcmp(clients[i].ip_addr, blk_ip) && !clients[i].exited){
									flag = TRUE;

									/* getting the list of all clients blocked by this client */
									cse4589_print_and_log("[%s:SUCCESS]\n", "BLOCKED");
									qsort(clients, n_reg, sizeof(struct client), comparator);
									int j, n = 0;
									for (j = 0; j < n_reg; j++){
										int k;
										for (k = 0; k < clients[i].n_blocked; k++){
											if (!strcmp(clients[j].ip_addr, clients[i].blocked[k]) && !clients[j].exited){
												cse4589_print_and_log("%-5d%-35s%-20s%-8d\n", ++n, clients[j].hostname, clients[j].ip_addr, clients[j].listen_port);
											}
										}
									}
									cse4589_print_and_log("[%s:END]\n", "BLOCKED");
									break;
								}
							}
							if (!flag){
								cse4589_print_and_log("[%s:ERROR]\n", "BLOCKED");
								cse4589_print_and_log("[%s:END]\n", "BLOCKED");
								continue;
							}
						}

						/* STATISTICS command */
						else if (!strcmp(cmd[0], "STATISTICS")){
							cse4589_print_and_log("[%s:SUCCESS]\n", "STATISTICS");
							qsort(clients, n_reg, sizeof(struct client), comparator);
							int i, n = 0;
							for (i = 0; i < n_reg; i++){
								if (clients[i].exited){
									continue;
								}
								char logged_status[12];
								if (!clients[i].logged_in){
									strcpy(logged_status, "logged-out");
								}
								else {
									strcpy(logged_status, "logged-in");
								}
								cse4589_print_and_log("%-5d%-35s%-8d%-8d%-8s\n", ++n, clients[i].hostname, clients[i].num_msg_sent, clients[i].num_msg_recv, logged_status);
							}
							cse4589_print_and_log("[%s:END]\n", "STATISTICS");
						}
					}

					/* checking if any new client is requesting connection on the server's listening port */
					else if (sock_index == server_socket){

						/* accepting the client's request and connecting */
						caddr_len = sizeof(cl_addr);
						fdaccept = accept(server_socket, (struct sockaddr *)&cl_addr, &caddr_len);
						if(fdaccept < 0){
							perror("SERVER: Accept failed");
						}

						/* finding the hostname and IP address of the client */
						char cl_hostname[HOSTNAME_SIZE], cl_ip[IP_SIZE];
						getnameinfo((struct sockaddr *) &cl_addr, caddr_len, cl_hostname, HOSTNAME_SIZE, NULL, 0, 0);
						inet_ntop(AF_INET, &(cl_addr.sin_addr), cl_ip, IP_SIZE);

						/* checking if this client is already registered */
						int i, flag = FALSE;
						for (i = 0; i < n_reg; i++){
							if (!strcmp(clients[i].ip_addr, cl_ip) && !clients[i].logged_in){
								clients[i].logged_in = TRUE;
								clients[i].fd = fdaccept;
								n_online++;
								flag = TRUE;
								break;
							}
						}
						if (flag){
							/* adding the file descriptor to watch list */
							FD_SET(fdaccept, &master_list);
							if (fdaccept > head_socket){
								head_socket = fdaccept;
							}
							continue;
						}

						/* updating the list of online clients */
						if (n_reg == MAX_CLIENTS){
							int i;
							for (i = 0; i < n_reg; i++){
								if (clients[i].exited){
									memset(&clients[i], '\0', sizeof(clients[i]));
									loc = i;
									break;
								}
							}
						}
						else {
							loc = n_reg;
							n_reg++;
						}
						clients[loc].fd = fdaccept;
						clients[loc].logged_in = TRUE;
						clients[loc].exited = FALSE;
						strcpy(clients[loc].hostname, cl_hostname);
						strcpy(clients[loc].ip_addr, cl_ip);
						FD_SET(fdaccept, &master_list);
						if(fdaccept > head_socket){
							head_socket = fdaccept;
						}
						n_online++;
					}

					/* processing commands from the existing clients */
					else {

						/* finding which client sent the command */
						int cl_idx;
						for (cl_idx = 0; cl_idx < n_reg; cl_idx++){
							if ((clients[cl_idx].fd == sock_index && !clients[cl_idx].stat)){
								break;
							}
						}

						/* initializing buffer to receive data from the client */
						char *cmd_buffer = (char*) malloc(sizeof(char)*(CMD_SIZE + MSG_SIZE));
						memset(cmd_buffer, '\0', CMD_SIZE + MSG_SIZE);

						/* reading data sent by the client */
						int len = CMD_SIZE + MSG_SIZE;
						if (recvall(sock_index, cmd_buffer, &len) < 0){
							close(sock_index);

							/* removing the file descriptor from watch list */
							FD_CLR(sock_index, &master_list);
							clients[cl_idx].stat = TRUE;
						}
						else {

							/* creating a copy of the received data */
							char buffer[CMD_SIZE + MSG_SIZE];
							memset(buffer, '\0', CMD_SIZE + MSG_SIZE);
							if (!strncmp(cmd_buffer, "SE", 2) || !strncmp(cmd_buffer, "BR", 2)){
								strcpy(buffer, cmd_buffer);
							}
							else {
								strcpy(buffer, strtok(cmd_buffer, "$$"));
							}

							/* handling LOGIN command from the client */
							if (!strncmp(&buffer[0], "PO", 2)){
								
								/* 1. updating the client's listening port number */
								if (!strncmp(&buffer[0], "POF", 3)){
									clients[cl_idx].listen_port = atoi(&buffer[3]);
									clients[cl_idx].logged_in = TRUE;
								}

								/* 2. sending the list of logged-in clients */

								/* creating a byte sequence of all the logged-in clients */
								char *list_buf = (char*) malloc(sizeof(char)*BUFFER_SIZE);
								memset(list_buf, '\0', BUFFER_SIZE);
								sprintf(list_buf, "%d", n_online);
								strcat(list_buf, " ");
								qsort(clients, n_reg, sizeof(struct client), comparator);
								int i;
								for (i = 0; i < n_reg; i++){
									if (!clients[i].logged_in || clients[i].exited){
										continue;
									}
									strcat(list_buf, clients[i].hostname);
									strcat(list_buf, " ");
									strcat(list_buf, clients[i].ip_addr);
									strcat(list_buf, " ");
									char tmp_port[PORT_SIZE];
									sprintf(tmp_port, "%d", clients[i].listen_port);
									strcat(list_buf, tmp_port);
									strcat(list_buf, " ");
								}
								strcat(list_buf, "$$");

								/* sending the details to the client */
								int le = strlen(list_buf);
								if (sendall(sock_index, list_buf, &le) < 0){
									perror("SERVER: [LOGIN] Failed to send list while client login");
								}

								/* 3. sending messages buffered for the client */

								/* checking if the client has any messages to receive */
								if (clients[cl_idx].n_buffered == 0){
									continue;
								}

								/* relaying buffered messages to the client */
								char buff_msg[clients[cl_idx].n_buffered * (CMD_SIZE + MSG_SIZE)];
								memset(buff_msg, '\0', clients[cl_idx].n_buffered * (CMD_SIZE + MSG_SIZE));
								sprintf(buff_msg, "BU %d", clients[cl_idx].n_buffered);
								strcat(buff_msg, " ");
								int j;
								for (j = 0; j < n_buff; j++){
									if (!buffered[j].sent && !strcmp(buffered[j].recv_ip, clients[cl_idx].ip_addr)){
										strcat(buff_msg, buffered[j].send_ip);
										strcat(buff_msg, " ");
										strcat(buff_msg, buffered[j].msg);
										strcat(buff_msg, " ");
										cse4589_print_and_log("[%s:SUCCESS]\n", "RELAYED");
										cse4589_print_and_log("msg from:%s, to:%s\n[msg]:%s\n", buffered[j].send_ip, buffered[j].recv_ip, buffered[j].msg);
										cse4589_print_and_log("[%s:END]\n", "RELAYED");
										buffered[j].sent = TRUE;
									}
								}
								strcat(buff_msg, "$$");

								if (clients[cl_idx].listen_fd == 0){
									struct addrinfo cl_hints, *cl_res;

									memset(&cl_hints, '\0', sizeof(cl_hints));
									cl_hints.ai_family = AF_INET;
									cl_hints.ai_socktype = SOCK_STREAM;

									char tmp_port[PORT_SIZE];
									sprintf(tmp_port, "%d", clients[cl_idx].listen_port);
									if (getaddrinfo(clients[cl_idx].ip_addr, tmp_port, &cl_hints, &cl_res) != 0){
										perror("SERVER: [LOGIN] Method getaddrinfo() failed");
									}

									int cl_socket;
									cl_socket = socket(cl_res->ai_family, cl_res->ai_socktype, cl_res->ai_protocol);
									if(cl_socket < 0){
										perror("SERVER: [LOGIN] Failed to create socket");
									}

									if(connect(cl_socket, cl_res->ai_addr, cl_res->ai_addrlen) < 0){
										perror("SERVER: [LOGIN] Connect failed");
									}

									clients[cl_idx].listen_fd = cl_socket;
								}

								int len = strlen(buff_msg);
								if (sendall(clients[cl_idx].listen_fd, buff_msg, &len) < 0){
									perror("SERVER: [LOGIN] Failed to send buffered messages to client");
								}

								free(list_buf);
							}

							/* handling REFRESH command from the client */
							else if (!strncmp(&buffer[0], "RF", 2)){

								/* creating a byte sequence of all the required details */
								char *refr_buf = (char*) malloc(sizeof(char)*BUFFER_SIZE);
								memset(refr_buf, '\0', BUFFER_SIZE);
								sprintf(refr_buf, "%d", n_online);
								strcat(refr_buf, " ");
								qsort(clients, n_reg, sizeof(struct client), comparator);
								int i;
								for (i = 0; i < n_reg; i++){
									if (!clients[i].logged_in || clients[i].exited){
										continue;
									}
									strcat(refr_buf, clients[i].hostname);
									strcat(refr_buf, " ");
									strcat(refr_buf, clients[i].ip_addr);
									strcat(refr_buf, " ");
									char tmp_port[PORT_SIZE];
									sprintf(tmp_port, "%d", clients[i].listen_port);
									strcat(refr_buf, tmp_port);
									strcat(refr_buf, " ");
								}
								strcat(refr_buf, "$$");

								/* sending the details to the client */
								int le = strlen(refr_buf);
								if (sendall(sock_index, refr_buf, &le) < 0){
									perror("SERVER: [REFRESH] Failed to send list to client");
								}

								free(refr_buf);
							}

							/* handling SEND command from the client */
							else if (!strncmp(&buffer[0], "SE", 2)){

								/* truncating the buffer to exclude $$ at the end */
								buffer[strlen(buffer) - 3] = '\0';

								/* tokenizing the received sequence */
								int argc = 0, msg_start_idx = 0;
								char *arg;
								arg = strtok(buffer, " ");
								char* split[MAX_CMD_LEN];
								memset(split, '\0', sizeof(split));
								while (arg){
									split[argc] = arg;
									if (argc < 2){
										msg_start_idx += strlen(arg) + 1;
									}
									argc += 1;
									if (argc == 2){
										break;
									}
									arg = strtok(NULL, " ");
								}

								/* incrementing the number of messages sent by the client */
								clients[cl_idx].num_msg_sent++;

								/* checking if the recipient has blocked the sender */
								int i, flag = FALSE;
								for (i = 0; i < n_reg; i++){
									if (!clients[i].exited && !strcmp(clients[i].ip_addr, split[1])){
										flag = TRUE;
										int j;
										for (j = 0; j < clients[i].n_blocked; j++){
											if (!strcmp(clients[i].blocked[j], clients[cl_idx].ip_addr)){
												flag = FALSE;
												break;
											}
										}
										break;
									}
								}
								if (!flag){
									continue;
								}

								/* buffering the message in case the recipient is not logged in */
								if (!clients[i].logged_in){
									strcpy(buffered[n_buff].send_ip, clients[cl_idx].ip_addr);
									strcpy(buffered[n_buff].recv_ip, clients[i].ip_addr);
									strcpy(buffered[n_buff].msg, &buffer[msg_start_idx]);
									buffered[n_buff].sent = FALSE;
									clients[i].n_buffered++;
									n_buff++;
									continue;
								}

								cse4589_print_and_log("[%s:SUCCESS]\n", "RELAYED");
								cse4589_print_and_log("msg from:%s, to:%s\n[msg]:%s\n", clients[cl_idx].ip_addr, clients[i].ip_addr, &buffer[msg_start_idx]);
								cse4589_print_and_log("[%s:END]\n", "RELAYED");

								/* incrementing the number of messages sent to the recipient */
								clients[i].num_msg_recv++;

								/* relaying the message to the recipient*/
								if (clients[i].listen_fd == 0){
									struct addrinfo cl_hints, *cl_res;

									memset(&cl_hints, '\0', sizeof(cl_hints));
									cl_hints.ai_family = AF_INET;
									cl_hints.ai_socktype = SOCK_STREAM;

									char tmp_port[PORT_SIZE];
									sprintf(tmp_port, "%d", clients[i].listen_port);
									if (getaddrinfo(clients[i].ip_addr, tmp_port, &cl_hints, &cl_res) != 0){
										perror("SERVER: [SEND] Method getaddrinfo() failed");
									}

									int cl_socket;
									cl_socket = socket(cl_res->ai_family, cl_res->ai_socktype, cl_res->ai_protocol);
									if(cl_socket < 0){
										perror("SERVER: [SEND] Failed to create socket");
									}

									if(connect(cl_socket, cl_res->ai_addr, cl_res->ai_addrlen) < 0){
										perror("SERVER: [SEND] Connect failed");
									}

									clients[i].listen_fd = cl_socket;
								}

								char send_msg[CMD_SIZE + MSG_SIZE];
								memset(send_msg, '\0', CMD_SIZE + MSG_SIZE);
								strcpy(send_msg, "SE");
								strcat(send_msg, " ");
								strcat(send_msg, clients[cl_idx].ip_addr);
								strcat(send_msg, " ");
								strcat(send_msg, &buffer[msg_start_idx]);
								strcat(send_msg, "$$");

								int le = strlen(send_msg);
								if (sendall(clients[i].listen_fd, send_msg, &le) < 0){
									perror("SERVER: [SEND] Failed to relay message to client");
								}
							}

							/* handling BROADCAST command from the client */
							else if (!strncmp(&buffer[0], "BR", 2)){

								/* truncating the buffer to exclude $$ at the end */
								buffer[strlen(buffer) - 3] = '\0';
								clients[cl_idx].num_msg_sent++;
								int msg_start_idx = 3;

								cse4589_print_and_log("[%s:SUCCESS]\n", "RELAYED");
								cse4589_print_and_log("msg from:%s, to:%s\n[msg]:%s\n", clients[cl_idx].ip_addr, "255.255.255.255", &buffer[msg_start_idx]);
								cse4589_print_and_log("[%s:END]\n", "RELAYED");

								int i;
								for (i = 0; i < n_reg; i++){

									/* not sending message to logged-out, exited clients and the sender */
									if (!clients[i].logged_in || clients[i].exited || !strcmp(clients[i].ip_addr, clients[cl_idx].ip_addr)){
										continue;
									}

									/* not sending message to the clients that have blocked the sender */
									int j, flag = TRUE;
									for (j = 0; j < clients[i].n_blocked; j++){
										if (!strcmp(clients[i].blocked[j], clients[cl_idx].ip_addr)){
											flag = FALSE;
											break;
										}
									}
									if (!flag){
										continue;
									}

									/* sending the message to the remaining clients*/
									if (clients[i].listen_fd == 0){
										struct addrinfo cl_hints, *cl_res;

										memset(&cl_hints, '\0', sizeof(cl_hints));
										cl_hints.ai_family = AF_INET;
										cl_hints.ai_socktype = SOCK_STREAM;

										char tmp_port[PORT_SIZE];
										sprintf(tmp_port, "%d", clients[i].listen_port);

										if (getaddrinfo(clients[i].ip_addr, tmp_port, &cl_hints, &cl_res) != 0){
											perror("SERVER: [BROADCAST] Method getaddrinfo() failed");
										}

										int cl_socket;
										cl_socket = socket(cl_res->ai_family, cl_res->ai_socktype, cl_res->ai_protocol);
										if(cl_socket < 0){
											perror("SERVER: [BROADCAST] Failed to create socket");
										}

										if(connect(cl_socket, cl_res->ai_addr, cl_res->ai_addrlen) < 0){
											perror("SERVER: [BROADCAST] Connect failed");
										}

										clients[i].listen_fd = cl_socket;
									}

									char brd_msg[CMD_SIZE + MSG_SIZE];
									memset(brd_msg, '\0', CMD_SIZE + MSG_SIZE);
									strcpy(brd_msg, "SE");
									strcat(brd_msg, " ");
									strcat(brd_msg, clients[cl_idx].ip_addr);
									strcat(brd_msg, " ");
									strcat(brd_msg, &buffer[msg_start_idx]);
									strcat(brd_msg, "$$");

									int le = strlen(brd_msg);
									if (sendall(clients[i].listen_fd, brd_msg, &le) < 0){
										perror("SERVER: [BROADCAST] Failed to send message to client");
									}
								}
							}

							/* handling BLOCK command from the client */
							else if (!strncmp(&buffer[0], "BL", 2)){
								strcpy(clients[cl_idx].blocked[clients[cl_idx].n_blocked], &buffer[2]);
								clients[cl_idx].n_blocked++;
							}

							/* handling UNBLOCK command from the client */
							else if (!strncmp(&buffer[0], "UB", 2)){
								int i;
								for (i = 0; i < clients[cl_idx].n_blocked; i++){
									if (!strcmp(clients[cl_idx].blocked[i], &buffer[2])){
										memset(clients[cl_idx].blocked[i], '\0', sizeof(clients[cl_idx].blocked[i]));
										int j;
										for (j = i; j < clients[cl_idx].n_blocked - 1; j++){
											memcpy(clients[cl_idx].blocked[j], clients[cl_idx].blocked[j + 1], sizeof(clients[cl_idx].blocked[j + 1]));
										}
										break;
									}
								}
								clients[cl_idx].n_blocked--;
							}

							/* handling LOGOUT command from the client */
							else if (!strncmp(&buffer[0], "LO", 2)){
								clients[cl_idx].logged_in = FALSE;
								FD_CLR(sock_index, &master_list);
								n_online--;
							}

							/* handling EXIT command from the client */
							else if (!strncmp(&buffer[0], "EX", 2)){
								clients[cl_idx].exited = TRUE;
								FD_CLR(sock_index, &master_list);
								n_online--;
							}
						}
						free(cmd_buffer);
					}
				}
			}
		}
	}
}


/**
 * function for client-side implementation, based on recitation files server.c and client.c
 *
 * @param  port Listening port number
 */
void client(char *port)
{
	int client_socket, head_socket, selret, sock_index, fdaccept=0, saddr_len, n_online=0, logged_in=FALSE, first_login=TRUE, server, n_blocked=0, n_fds=0;
	char blocked[MAX_CLIENTS][IP_SIZE];
	struct sockaddr_in sv_addr;
	struct addrinfo hints, *res;
	fd_set master_list, watch_list;

	/* setting up hints structure */
	memset(&hints, '\0', sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	/* filling up address structures */
	if (getaddrinfo(NULL, port, &hints, &res) != 0){
		perror("CLIENT: Method getaddrinfo() failed");
	}

	/* creating a socket */
	client_socket = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if(client_socket < 0){
		perror("CLIENT: Failed to create socket");
	}

	/* associating the socket with a port */
	if(bind(client_socket, res->ai_addr, res->ai_addrlen) < 0 ){
		perror("CLIENT: Bind failed");
	}

	freeaddrinfo(res);

	/* listening on the socket */
	if(listen(client_socket, BACKLOG) < 0){
		perror("CLIENT: Unable to listen on port");
	}

	/* zero selecting the FD sets */
	FD_ZERO(&master_list);
	FD_ZERO(&watch_list);

	/* registering the server listening socket */
	FD_SET(client_socket, &master_list);

	/* registering STDIN to process commands from the shell */
	FD_SET(STDIN, &master_list);

	head_socket = client_socket;

	while (TRUE){

		memcpy(&watch_list, &master_list, sizeof(master_list));

		printf("\n[PA1-Client@CSE589]$ ");
		fflush(stdout);

		/* multiplexing using select() system call */
		selret = select(head_socket + 1, &watch_list, NULL, NULL, NULL);
		if (selret < 0){
			perror("CLIENT: Select failed");
		}

		/* checking if we have any sockets/STDIN to process */
		if (selret > 0){

			n_fds = 0;

			/* looping through all socket descriptors to check which ones are ready */
			for (sock_index = 0; sock_index <= head_socket; sock_index++){

				if (n_fds == selret){
					break;
				}

				if (FD_ISSET(sock_index, &watch_list)){

					n_fds++;

					/* checking for any new commands on STDIN */
					if (sock_index == STDIN){

						/* getting commands from the shell */
						char inp[CMD_SIZE + MSG_SIZE];
						if (fgets(inp, CMD_SIZE + MSG_SIZE - 1, stdin) == NULL){
							exit(-1);
						}
						if (!strcmp(inp, "\n")){
							continue;
						}
						int inp_len = strlen(inp);

						/* tokenizing the input */
						int argc = 0, arg1_start_idx = 0, arg2_start_idx = 0;
						char *arg = strtok(inp, "\n");
						arg = strtok(arg, " ");
						char* cmd[MAX_CMD_LEN];
						memset(cmd, '\0', sizeof(cmd));
						while (arg){
							cmd[argc] = arg;
							if (argc < 1){
								arg1_start_idx += strlen(arg) + 1;
							}
							if (argc < 2){
								arg2_start_idx += strlen(arg) + 1;
							}
							argc += 1;
							arg = strtok(NULL, " ");
						}

						/* AUTHOR command */
						if (!strcmp(cmd[0], "AUTHOR")){
							cse4589_print_and_log("[%s:SUCCESS]\n", "AUTHOR");
							cse4589_print_and_log("I, %s, have read and understood the course academic integrity policy.\n", "neelamra");
							cse4589_print_and_log("[%s:END]\n", "AUTHOR");
						}

						/* IP command */
						else if (!strcmp(cmd[0], "IP")){
							get_ipaddr();
						}

						/* PORT command */
						else if (!strcmp(cmd[0], "PORT")){
							cse4589_print_and_log("[%s:SUCCESS]\n", "PORT");
							cse4589_print_and_log("PORT:%d\n", atoi(port));
							cse4589_print_and_log("[%s:END]\n", "PORT");
						}

						/* LIST command */
						else if (!strcmp(cmd[0], "LIST")){
							if (!logged_in){
								cse4589_print_and_log("[%s:ERROR]\n", "LIST");
								cse4589_print_and_log("[%s:END]\n", "LIST");
								continue;
							}
							cse4589_print_and_log("[%s:SUCCESS]\n", "LIST");
							int i;
							for (i = 0; i < n_online; i++){
								cse4589_print_and_log("%-5d%-35s%-20s%-8d\n", i + 1, clients[i].hostname, clients[i].ip_addr, clients[i].listen_port);
							}
							cse4589_print_and_log("[%s:END]\n", "LIST");
						}

						/* LOGIN command */
						else if (!strcmp(cmd[0], "LOGIN")){
							if (logged_in){
								cse4589_print_and_log("[%s:ERROR]\n", "LOGIN");
								cse4589_print_and_log("[%s:END]\n", "LOGIN");
								continue;
							}

							char server_ip[IP_SIZE];
							strcpy(server_ip, cmd[1]);

							char server_port[PORT_SIZE];
							strcpy(server_port, cmd[2]);

							/* checking if the server IP and port number are valid */
							if (!isValidIP(cmd[1]) || !isValidDigit(cmd[2])){
								cse4589_print_and_log("[%s:ERROR]\n", "LOGIN");
								cse4589_print_and_log("[%s:END]\n", "LOGIN");
								continue;
							}

							struct addrinfo hints, *res;

							/* setting up hints structure */
							memset(&hints, '\0', sizeof(hints));
							hints.ai_family = AF_INET;
							hints.ai_socktype = SOCK_STREAM;

							/* filling up address structures*/
							if (getaddrinfo(server_ip, server_port, &hints, &res) != 0){
								perror("CLIENT: [LOGIN] Method getaddrinfo() failed");
								cse4589_print_and_log("[%s:ERROR]\n", "LOGIN");
								cse4589_print_and_log("[%s:END]\n", "LOGIN");
								continue;
							}

							/* creating a socket */
							server = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
							if(server < 0){
								perror("CLIENT: [LOGIN] Failed to create socket");
								cse4589_print_and_log("[%s:ERROR]\n", "LOGIN");
								cse4589_print_and_log("[%s:END]\n", "LOGIN");
								continue;
							}

							/* connecting to the server */
							if(connect(server, res->ai_addr, res->ai_addrlen) < 0){
								perror("CLIENT: [LOGIN] Failed to connect");
								cse4589_print_and_log("[%s:ERROR]\n", "LOGIN");
								cse4589_print_and_log("[%s:END]\n", "LOGIN");
								continue;
							}

							freeaddrinfo(res);
							logged_in = TRUE;

							char pfx[15] = "PO";
							if (first_login){
								strcat(pfx, "F");
								strcat(pfx, port);
							}
							strcat(pfx, "$$");
							int le = sizeof(pfx);

							/* sending the listening port number to the server */
							if (sendall(server, pfx, &le) < 0){
								perror("CLIENT: [LOGIN] Failed to send listening port");
								cse4589_print_and_log("[%s:ERROR]\n", "LOGIN");
								cse4589_print_and_log("[%s:END]\n", "LOGIN");
								continue;
							}

							first_login = FALSE;

							/* initializing buffer to receive the list of logged-in clients */
							char *list_buffer = (char*) malloc(sizeof(char)*BUFFER_SIZE);
							memset(list_buffer, '\0', BUFFER_SIZE);

							/* receiving list of clients from the server */
							int len = BUFFER_SIZE;
							if(recvall(server, list_buffer, &len) < 0){
								perror("CLIENT: [LOGIN] Failed to receive list of logged-in clients");
								cse4589_print_and_log("[%s:ERROR]\n", "LOGIN");
								cse4589_print_and_log("[%s:END]\n", "LOGIN");
								continue;
							}

							/* tokenizing the received byte sequence */
							int cnt = 0;
							char *val = strtok(list_buffer, "$$");
							val = strtok(val, " ");
							char* split[MAX_CLIENTS * 4];
							memset(split, '\0', sizeof(split));
							while (val){
								split[cnt] = val;
								cnt += 1;
								val = strtok(NULL, " ");
							}

							/* retrieving the list of logged-in clients */
							n_online = atoi(split[0]);
							int i, n = 0;
							for (i = 0; i < n_online; i++){
								strcpy(clients[i].hostname, split[3*i + 1]);
								strcpy(clients[i].ip_addr, split[3*i + 2]);
								clients[i].listen_port = atoi(split[3*i + 3]);
							}

							cse4589_print_and_log("[%s:SUCCESS]\n", "LOGIN");
							cse4589_print_and_log("[%s:END]\n", "LOGIN");

							free(list_buffer);
						}

						/* REFRESH command */
						else if (!strcmp(cmd[0], "REFRESH")){
							if (!logged_in){
								cse4589_print_and_log("[%s:ERROR]\n", "REFRESH");
								cse4589_print_and_log("[%s:END]\n", "REFRESH");
								continue;
							}

							char refresh[5] = "RF";
							strcat(refresh, "$$");
							int le = sizeof(refresh);
							if (sendall(server, refresh, &le) < 0){
								perror("CLIENT: [REFRESH] Failed to send refresh request");
								cse4589_print_and_log("[%s:ERROR]\n", "REFRESH");
								cse4589_print_and_log("[%s:END]\n", "REFRESH");
								continue;
							}

							/* initializing buffer to receive the list of logged-in clients */
							char *refr_buffer = (char*) malloc(sizeof(char)*BUFFER_SIZE);
							memset(refr_buffer, '\0', BUFFER_SIZE);

							/* receiving list of clients from the server */
							int len = BUFFER_SIZE;
							if(recvall(server, refr_buffer, &len) < 0){
								perror("CLIENT: [REFRESH] Failed to receive refreshed list of clients");
								cse4589_print_and_log("[%s:ERROR]\n", "REFRESH");
								cse4589_print_and_log("[%s:END]\n", "REFRESH");
								continue;
							}

							/* tokenizing the received byte sequence */
							int cnt = 0;
							char *val = strtok(refr_buffer, "$$");
							val = strtok(val, " ");
							char* split[MAX_CLIENTS * 4];
							memset(split, '\0', sizeof(split));
							while (val){
								split[cnt] = val;
								cnt += 1;
								val = strtok(NULL, " ");
							}

							/* retrieving the list of logged-in clients */
							n_online = atoi(split[0]);
							int i, n = 0;
							for (i = 0; i < n_online; i++){
								memset(&clients[i], '\0', sizeof(clients[i]));
								strcpy(clients[i].hostname, split[3*i + 1]);
								strcpy(clients[i].ip_addr, split[3*i + 2]);
								clients[i].listen_port = atoi(split[3*i + 3]);
							}

							cse4589_print_and_log("[%s:SUCCESS]\n", "REFRESH");
							cse4589_print_and_log("[%s:END]\n", "REFRESH");

							free(refr_buffer);
						}

						/* SEND command */
						else if (!strcmp(cmd[0], "SEND")){
							if (!logged_in){
								cse4589_print_and_log("[%s:ERROR]\n", "SEND");
								cse4589_print_and_log("[%s:END]\n", "SEND");
								continue;
							}

							char rcpt_ip[IP_SIZE];
							strcpy(rcpt_ip, cmd[1]);

							/* checking if the IP address is valid */
							if (!isValidIP(cmd[1])){
								cse4589_print_and_log("[%s:ERROR]\n", "SEND");
								cse4589_print_and_log("[%s:END]\n", "SEND");
								continue;
							}

							/* checking if there is a client with this IP in the local list */
							int i, flag = FALSE;
							for (i = 0; i < n_online; i++){
								if (!strcmp(clients[i].ip_addr, rcpt_ip)){
									flag = TRUE;
									break;
								}
							}
							if (!flag){
								cse4589_print_and_log("[%s:ERROR]\n", "SEND");
								cse4589_print_and_log("[%s:END]\n", "SEND");
								continue;
							}

							/* retrieving message from the shell */
							char msg[MSG_SIZE];
							strcpy(msg, "");
							while (arg2_start_idx < inp_len){
								if (!strcmp(&inp[arg2_start_idx], "\0")){
									strcat(msg, " ");
									arg2_start_idx++;
								}
								else {
									strcat(msg, &inp[arg2_start_idx]);
									arg2_start_idx += strlen(&inp[arg2_start_idx]);
								}
							}

							/* sending the message to the server */
							char snd[CMD_SIZE + MSG_SIZE] = "SE";
							strcat(snd, " ");
							strcat(snd, rcpt_ip);
							strcat(snd, " ");
							strcat(snd, msg);
							strcat(snd, "$$");

							int le = sizeof(snd);
							if (sendall(server, snd, &le) < 0){
								perror("CLIENT: [SEND] Failed to send SEND request");
								cse4589_print_and_log("[%s:ERROR]\n", "SEND");
							}
							else {
								cse4589_print_and_log("[%s:SUCCESS]\n", "SEND");
							}
							cse4589_print_and_log("[%s:END]\n", "SEND");
						}

						/* BROADCAST command */
						else if (!strcmp(cmd[0], "BROADCAST")){
							if (!logged_in){
								cse4589_print_and_log("[%s:ERROR]\n", "BROADCAST");
								cse4589_print_and_log("[%s:END]\n", "BROADCAST");
								continue;
							}

							/* retrieving message from the shell */
							char msg[MSG_SIZE];
							strcpy(msg, "");
							while (arg1_start_idx < inp_len){
								if (!strcmp(&inp[arg1_start_idx], "\0")){
									strcat(msg, " ");
									arg1_start_idx++;
								}
								else {
									strcat(msg, &inp[arg1_start_idx]);
									arg1_start_idx += strlen(&inp[arg1_start_idx]);
								}
							}

							/* sending the message to the server */
							char brd[CMD_SIZE + MSG_SIZE] = "BR";
							strcat(brd, " ");
							strcat(brd, msg);
							strcat(brd, "$$");

							int le = sizeof(brd);
							if (sendall(server, brd, &le) < 0){
								perror("CLIENT: [BROADCAST] Failed to send broadcast request");
								cse4589_print_and_log("[%s:ERROR]\n", "BROADCAST");
							}
							else {
								cse4589_print_and_log("[%s:SUCCESS]\n", "BROADCAST");
							}
							cse4589_print_and_log("[%s:END]\n", "BROADCAST");
						}

						/* BLOCK command */
						else if (!strcmp(cmd[0], "BLOCK")){
							if (!logged_in){
								cse4589_print_and_log("[%s:ERROR]\n", "BLOCK");
								cse4589_print_and_log("[%s:END]\n", "BLOCK");
								continue;
							}

							char blk_ip[IP_SIZE];
							strcpy(blk_ip, cmd[1]);

							/* checking if the IP address is valid */
							if (!isValidIP(cmd[1])){
								cse4589_print_and_log("[%s:ERROR]\n", "BLOCK");
								cse4589_print_and_log("[%s:END]\n", "BLOCK");
								continue;
							}

							/* checking if there is a client with this IP in the local list */
							int i, flag = FALSE;
							for (i = 0; i < n_online; i++){
								if (!strcmp(clients[i].ip_addr, blk_ip)){
									flag = TRUE;
									int j;
									for (j = 0; j < n_blocked; j++){
										if ((!strcmp(blocked[j], blk_ip))){
											flag = FALSE;
											break;
										}
									}
									break;
								}
							}
							if (!flag){
								cse4589_print_and_log("[%s:ERROR]\n", "BLOCK");
								cse4589_print_and_log("[%s:END]\n", "BLOCK");
								continue;
							}

							strcpy(blocked[n_blocked], blk_ip);
							n_blocked++;

							/* informing the server about blocking this IP */
							char blk[25] = "BL";
							strcat(blk, blk_ip);
							strcat(blk, "$$");
							int le = sizeof(blk);
							if (sendall(server, blk, &le) < 0){
								perror("CLIENT: [BLOCK] Failed to send block request");
								cse4589_print_and_log("[%s:ERROR]\n", "BLOCK");
							}
							else {
								cse4589_print_and_log("[%s:SUCCESS]\n", "BLOCK");
							}
							cse4589_print_and_log("[%s:END]\n", "BLOCK");
						}

						/* UNBLOCK command */
						else if (!strcmp(cmd[0], "UNBLOCK")){
							if (!logged_in){
								cse4589_print_and_log("[%s:ERROR]\n", "UNBLOCK");
								cse4589_print_and_log("[%s:END]\n", "UNBLOCK");
								continue;
							}

							char unblk_ip[IP_SIZE];
							strcpy(unblk_ip, cmd[1]);

							/* checking if the IP address is valid */
							if (!isValidIP(cmd[1])){
								cse4589_print_and_log("[%s:ERROR]\n", "UNBLOCK");
								cse4589_print_and_log("[%s:END]\n", "UNBLOCK");
								continue;
							}

							/* checking if there is a client with this IP in the local list */
							int i, flag = FALSE;
							for (i = 0; i < n_online; i++){
								if (!strcmp(clients[i].ip_addr, unblk_ip)){
									int j;
									for (j = 0; j < n_blocked; j++){
										if (!strcmp(blocked[j], unblk_ip)){
											memset(blocked[j], '\0', sizeof(blocked[j]));
											int k;
											for (k = j; k < n_blocked - 1; k++){
												memcpy(blocked[k], blocked[k + 1], sizeof(blocked[k + 1]));
											}
											n_blocked--;
											flag = TRUE;
											break;
										}
									}
									break;
								}
							}
							if (!flag){
								cse4589_print_and_log("[%s:ERROR]\n", "UNBLOCK");
								cse4589_print_and_log("[%s:END]\n", "UNBLOCK");
								continue;
							}

							/* informing the server about unblocking this IP */
							char unblk[25] = "UB";
							strcat(unblk, unblk_ip);
							strcat(unblk, "$$");
							int le = sizeof(unblk);
							if (sendall(server, unblk, &le) < 0){
								perror("CLIENT: [UNBLOCK] Failed to send unblock request");
								cse4589_print_and_log("[%s:ERROR]\n", "UNBLOCK");
							}
							else {
								cse4589_print_and_log("[%s:SUCCESS]\n", "UNBLOCK");
							}
							cse4589_print_and_log("[%s:END]\n", "UNBLOCK");
						}

						/* LOGOUT command */
						else if (!strcmp(cmd[0], "LOGOUT")){
							if (!logged_in){
								cse4589_print_and_log("[%s:ERROR]\n", "LOGOUT");
								cse4589_print_and_log("[%s:END]\n", "LOGOUT");
								continue;
							}

							char logout[5] = "LO";
							strcat(logout, "$$");
							int le = sizeof(logout);
							if (sendall(server, logout, &le) < 0){
								perror("CLIENT [LOGOUT]: Failed to send logout request");
								cse4589_print_and_log("[%s:ERROR]\n", "LOGOUT");
							}
							else {
								logged_in = FALSE;
								cse4589_print_and_log("[%s:SUCCESS]\n", "LOGOUT");
							}
							cse4589_print_and_log("[%s:END]\n", "LOGOUT");
						}

						/* EXIT command */
						else if (!strcmp(cmd[0], "EXIT")){
							char exit[5] = "EX";
							strcat(exit, "$$");
							int le = sizeof(exit);
							if (sendall(server, exit, &le) < 0){
								perror("CLIENT [EXIT]: Failed to send exit request");
								cse4589_print_and_log("[%s:ERROR]\n", "EXIT");
							}
							else {
								cse4589_print_and_log("[%s:SUCCESS]\n", "EXIT");
							}
							cse4589_print_and_log("[%s:END]\n", "EXIT");
							return;
						}

						/* SENDFILE command */
						else if (!strcmp(cmd[0], "SENDFILE")){
/*							if (!logged_in){
								cse4589_print_and_log("[%s:ERROR]\n", "SENDFILE");
								cse4589_print_and_log("[%s:END]\n", "SENDFILE");
								continue;
							}*/

							char rcpt_ip[IP_SIZE];
							strcpy(rcpt_ip, cmd[1]);

							/* checking if the IP address is valid */
/*							if (!isValidIP(cmd[1])){
								cse4589_print_and_log("[%s:ERROR]\n", "SENDFILE");
								cse4589_print_and_log("[%s:END]\n", "SENDFILE");
								continue;
							}*/

							/* checking if there is a client with this IP in the local list */
							int i, flag = FALSE;
							for (i = 0; i < n_online; i++){
								if (!strcmp(clients[i].ip_addr, rcpt_ip)){
									flag = TRUE;
									break;
								}
							}
							if (!flag){
								cse4589_print_and_log("[%s:ERROR]\n", "SENDFILE");
								cse4589_print_and_log("[%s:END]\n", "SENDFILE");
								continue;
							}

							if (clients[i].listen_fd == 0){
								struct addrinfo cl_hints, *cl_res;
								memset(&cl_hints, '\0', sizeof(cl_hints));
								cl_hints.ai_family = AF_INET;
								cl_hints.ai_socktype = SOCK_STREAM;

								char tmp_port[PORT_SIZE];
								sprintf(tmp_port, "%d", clients[i].listen_port);

								if (getaddrinfo(clients[i].ip_addr, tmp_port, &cl_hints, &cl_res) != 0){
									perror("CLIENT: [SENDFILE] Method getaddrinfo() failed");
									cse4589_print_and_log("[%s:ERROR]\n", "SENDFILE");
									cse4589_print_and_log("[%s:END]\n", "SENDFILE");
									continue;
								}

								int cl_socket;
								cl_socket = socket(cl_res->ai_family, cl_res->ai_socktype, cl_res->ai_protocol);
								if(cl_socket < 0){
									perror("Failed to create socket");
									cse4589_print_and_log("[%s:ERROR]\n", "SENDFILE");
									cse4589_print_and_log("[%s:END]\n", "SENDFILE");
								}

								if(connect(cl_socket, cl_res->ai_addr, cl_res->ai_addrlen) < 0){
									perror("Connect failed");
									cse4589_print_and_log("[%s:ERROR]\n", "SENDFILE");
									cse4589_print_and_log("[%s:END]\n", "SENDFILE");
								}

								clients[i].listen_fd = cl_socket;
							}

							FILE *fp;
							if ((fp = fopen(cmd[2], "r")) == NULL){
								cse4589_print_and_log("[%s:ERROR]\n", "SENDFILE");
								cse4589_print_and_log("[%s:END]\n", "SENDFILE");
								continue;
							}

							char init[20];
							strcpy(init, "FL");
							strcat(init, " ");
							strcat(init, cmd[2]);
							strcat(init, "$$");
							int init_len = sizeof(init);
							if (sendall(clients[i].listen_fd, init, &init_len) < 0){
								perror("Failed to SEND message to client");
								cse4589_print_and_log("[%s:ERROR]\n", "SENDFILE");
								cse4589_print_and_log("[%s:END]\n", "SENDFILE");
								continue;
							}

							char tmp_buf[100000];
							memset(tmp_buf, '\0', sizeof(tmp_buf));
							int buf_len = sizeof(tmp_buf);
							flag = FALSE;
							while (fread(tmp_buf, 1, sizeof(tmp_buf), fp)){
								if (sendall(clients[i].listen_fd, tmp_buf, &buf_len) < 0){
									perror("Failed to SEND message to client");
									cse4589_print_and_log("[%s:ERROR]\n", "SENDFILE");
									cse4589_print_and_log("[%s:END]\n", "SENDFILE");
									flag = TRUE;
									continue;
								}
							}
							if (flag){
								continue;
							}

							char fin[3];
							strcpy(fin, "$$");
							int fin_len = sizeof(fin);
							if (sendall(clients[i].listen_fd, fin, &fin_len) < 0){
								perror("Failed to SEND message to client");
								cse4589_print_and_log("[%s:ERROR]\n", "SENDFILE");
								cse4589_print_and_log("[%s:END]\n", "SENDFILE");
								continue;
							}

							cse4589_print_and_log("[%s:SUCCESS]\n", "SENDFILE");
							cse4589_print_and_log("[%s:END]\n", "SENDFILE");

							fclose(fp);
						}
					}

					/* checking if server or any client is requesting connection on the client's listening port */
					else if (sock_index == client_socket){

						/* accepting the request and connecting */
						saddr_len = sizeof(sv_addr);
						fdaccept = accept(client_socket, (struct sockaddr *)&sv_addr, &saddr_len);
						if(fdaccept < 0){
							perror("CLIENT: Accept failed");
						}

						/* adding the file descriptor to watch list */
						FD_SET(fdaccept, &master_list);
						if(fdaccept > head_socket){
							head_socket = fdaccept;
						}

						printf("Accepted %d\n", fdaccept);
					}

					/* receiving something on the listening port */
					else {

						/* initializing buffer to receive data */
//						char *recv_buffer = (char*) malloc(sizeof(char)*(CMD_SIZE + MSG_SIZE)*5);
//						memset(recv_buffer, '\0', (CMD_SIZE + MSG_SIZE)*5);
						memset(file_buf, '\0', sizeof(file_buf));

						/* reading data sent on the listening port */
						int len = MAX_FILE_SIZE + BUFFER_SIZE;// 5*(CMD_SIZE + MSG_SIZE);
						if(recvall(sock_index, file_buf, &len) < 0){
							close(sock_index);

							/* removing the file descriptor from watch list */
							FD_CLR(sock_index, &master_list);
						}
						else {
							char buffer[5*(CMD_SIZE + MSG_SIZE)];
							memset(buffer, '\0', 5*(CMD_SIZE + MSG_SIZE));
							if (strncmp(&file_buf[0], "FL", 2) != 0){
								strcpy(buffer, file_buf);
							}

							/* checking if there is a message relayed by the server */
							if (!strncmp(&buffer[0], "SE", 2)){

								/* tokenizing the received sequence */
								buffer[strlen(buffer) - 2] = '\0';
								int argc = 0, msg_start_idx = 0;
								char *arg; 
								arg = strtok(buffer, " ");
								char* split[MAX_CMD_LEN];
								memset(split, '\0', sizeof(split));
								while (arg){
									split[argc] = arg;
									msg_start_idx += strlen(arg) + 1;
									argc += 1;
									if (argc == 2){
										break;
									}
									arg = strtok(NULL, " ");
								}

								cse4589_print_and_log("[%s:SUCCESS]\n", "RECEIVED");
								cse4589_print_and_log("msg from:%s\n[msg]:%s\n", split[1], &buffer[msg_start_idx]);
								cse4589_print_and_log("[%s:END]\n", "RECEIVED");
							}

							/* receiving any messages buffered when client logged-out */
							else if (!strncmp(&buffer[0], "BU", 2)){

								/* tokenizing the received sequence */
								int argc = 0;
								char *arg;
								arg = strtok(buffer, " ");
								char* split[15];
								memset(split, '\0', sizeof(split));
								while (arg){
									split[argc] = arg;
									argc += 1;
									arg = strtok(NULL, " ");
								}

								/* retrieving the buffered messages one by one */
								int n_msgs = atoi(split[1]);
								int i;
								for (i = 0; i < n_msgs; i++){
									cse4589_print_and_log("[%s:SUCCESS]\n", "RECEIVED");
									cse4589_print_and_log("msg from:%s\n[msg]:%s\n", split[2*i + 2], split[2*i + 3]);
									cse4589_print_and_log("[%s:END]\n", "RECEIVED");
								}
							}

							/* receiving P2P file from fellow client */
							else if (!strncmp(&file_buf[0], "FL", 2)){

								printf("here\n");

								printf("came here %d\n", strlen(file_buf));

								/* tokenizing the received sequence, code from rec2.pdf page 4 */
								file_buf[strlen(file_buf) - 2] = '\0';
								int argc = 0, txt_start_idx = 0;
								char *arg; 
								arg = strtok(file_buf, " ");
								char* split[MAX_CMD_LEN];
								memset(split, '\0', sizeof(split));
								while (arg){
									split[argc] = arg;
									txt_start_idx += strlen(arg) + 1;
									argc += 1;
									if (argc == 2){
										break;
									}
									arg = strtok(NULL, " ");
								}

								printf("start_idx %d\n", txt_start_idx);

								FILE *fp;
//								char file_buf[BUFFER_SIZE];
								fp = fopen(split[1], "w");
//								int le = BUFFER_SIZE, x;
//								printf("entering loop\n");
/*								while (TRUE){
									printf("%s %d\n", file_buf, x);
									if ((x = recvall(sock_index, file_buf, &le)) < 0){
										perror("Failed to receive file from the client");
										break;
									}
									fputs(file_buf, fp);
								}*/

								fputs(&file_buf[txt_start_idx], fp);

								fclose(fp);
							}

							else {
								printf("in else's else %d\n", sock_index);
							}
						}
//						free(file_buf);
					}
				}
			}
		}
	}
}


/**
 * function for IP command
 *
 * creates a UDP socket as discussed in rec2.pdf page 5
 */
void get_ipaddr()
{
	char *remote_server_ip = "8.8.8.8";
	int remote_server_port = 53;
	struct sockaddr_in remote_server;

	/* setting up remote server structure */
	memset(&remote_server, '\0', sizeof(remote_server));
	remote_server.sin_family = AF_INET;
	remote_server.sin_port = htons(remote_server_port);
	inet_pton(AF_INET, remote_server_ip, &remote_server.sin_addr);

	/* creating a socket */
	int udp_socket = socket(AF_INET, SOCK_DGRAM, 0);
	if (udp_socket < 0){
		perror("[IP] Cannot create UDP socket");
		cse4589_print_and_log("[%s:ERROR]\n", "IP");
		cse4589_print_and_log("[%s:END]\n", "IP");
		return;
	}

	/* connecting to the remote server */
	if (connect(udp_socket, (struct sockaddr*) &remote_server, sizeof(remote_server)) < 0){
		perror("[IP] Remote server connect failed");
		cse4589_print_and_log("[%s:ERROR]\n", "IP");
		cse4589_print_and_log("[%s:END]\n", "IP");
		return;
	}

	/* finding the ip address */
	socklen_t len = sizeof(remote_server);
	if (getsockname(udp_socket, (struct sockaddr*) &remote_server, &len) < 0){
		perror("[IP] Method getsockname() failed");
		cse4589_print_and_log("[%s:ERROR]\n", "IP");
		cse4589_print_and_log("[%s:END]\n", "IP");
		return;
	}
	char ip_addr[IP_SIZE];
	inet_ntop(AF_INET, &remote_server.sin_addr, ip_addr, IP_SIZE);
	close(udp_socket);

	cse4589_print_and_log("[%s:SUCCESS]\n", "IP");
	cse4589_print_and_log("IP:%s\n", ip_addr);
	cse4589_print_and_log("[%s:END]\n", "IP");

	return;
}


/**
 * function for comparing listening ports of clients
 *
 * @param  c1 First client struct
 * @param  c2 Second client struct
 * @return difference between their listening port numbers
 *
 * code from https://www.geeksforgeeks.org/c-program-to-store-student-records-as-structures-and-sort-them-by-age-or-id/
 */
int comparator(const void *c1, const void *c2)
{
	return (((struct client*) c1)->listen_port - ((struct client*) c2)->listen_port);
}


/**
 * function for verifying the validity of an IP address
 *
 * @param ip_addr IP address
 * @return TRUE or FALSE
 *
 * code from https://www.geeksforgeeks.org/program-to-validate-an-ip-address/
 */
int isValidIP(char *ip_addr)
{
	char dot[2], last[2];
	strcpy(dot, ".");
	strcpy(last, &ip_addr[strlen(ip_addr) - 1]);
	if (ip_addr == NULL || !strcmp(dot, last)){
		return FALSE;
	}
	int i, num, dots = 0;
	char *ptr = strtok(ip_addr, ".");
	if (ptr == NULL){
		return FALSE;
	}
	while (ptr){

		/* checking if the IP address has non-numeric characters */
		if (!isValidDigit(ptr)){
			return FALSE;
		}

		num = atoi(ptr);

		/* checking if the numbers are between 0 and 255 (inclusive)*/
		if (num >= 0 && num <= 255){
			ptr = strtok(NULL, ".");
			if (ptr != NULL){
				++dots;
			}
		}
		else {
			return FALSE;
		}
	}

	/* checking if the given IP address has three dots */
	if (dots != 3){
		return FALSE;
	}
	return TRUE;
}


/**
 * function for verifying the if a string contains only digits
 *
 * @param str String
 * @return TRUE or FALSE
 *
 * code from https://www.geeksforgeeks.org/program-to-validate-an-ip-address/
 */
int isValidDigit(char *str)
{
	while (*str){
		if (*str >= '0' && *str <= '9'){
			++str;
		}
		else {
			return FALSE;
		}
	}
	return TRUE;
}


/**
 * function for handling partial sends
 *
 * @param s Socket descriptor to send to
 * @param buf Data to be sent
 * @param len Length of buf
 * @return -1 on failure or 0 on success
 *
 * code from http://beej.us/guide/bgnet/html/#sendall
 */
int sendall(int s, char *buf, int *len)
{
	int total = 0;
	int bytesleft = *len;
	int n;
	while (total < *len){
		n = send(s, buf+total, bytesleft, 0);
		if (n == -1){
			break;
		}
		total += n;
		bytesleft -= n;
	}
	*len = total;
	return n == -1? -1 : 0;
}


/**
 * function for handling partial receives
 *
 * @param s Socket descriptor to read from
 * @param buf Buffer into which data has to be received
 * @param len Length of buf
 * @return -1 on failure or 0 on success
 *
 * code based on sendall() function defined above
 */
int recvall(int s, char *buf, int *len)
{
	int total = 0;
	int bytesleft = *len;
	int n;
	int t = 0;
	while (total < *len){
		t++;
		if (t == 50){
			return -1;
		}
		n = recv(s, buf+total, bytesleft, 0);
		int le = strlen(buf);
		if (n == -1 || !strcmp(&buf[le - 2], "$$")){
			break;
		}
		total += n;
		bytesleft -= n;
	}
	*len = total;
	return n == -1? -1 : 0;
}


/**
 * main function
 *
 * @param  argc Number of arguments
 * @param  argv The argument list
 * @return 0 EXIT_SUCCESS
 */
int main(int argc, char **argv)
{
	/*Init. Logger*/
	cse4589_init_log(argv[2]);

	/*Clear LOGFILE*/
	fclose(fopen(LOGFILE, "w"));

	/*Start Here*/
	if (!strcmp(argv[1], "s")){
		server(argv[2]);
	}
	else if (!strcmp(argv[1], "c")){
		client(argv[2]);
	}
	return 0;
}

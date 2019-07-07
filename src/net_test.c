#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

#include <signal.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "socket_helper.h"

#define LISTENER_FD_IDX 0
#define SNIFF_FD_IDX    1

#define TRUE             1 //dell me
#define FALSE            0
#define MAX_PORT_CHARS 6
#define MASTER_PORT    "23232"
#define MAX_CONNECTIONS 20

void test_client() {

}

typedef struct{
	char ip_addr[INET6_ADDRSTRLEN];
	char port[MAX_PORT_CHARS];
} reg_info_t;

typedef struct {

} result_t;

typedef union {
	reg_info_t reg;
	result_t result;
} ctrl_data_packet_t;

typedef enum {
	STOP,
	RUN_PING = 0x5,
	REGISTER_CLIENT,
	START_MULTICAST_SERVER,
	START_MULTICAST_CLIENT,
	ACCEPT,
	REJECT,
	RESULT
} ctrl_commands_t;

typedef struct {
	uint32_t packet_len;
	uint16_t command;
	ctrl_data_packet_t data;
} ctr_packet_t;

typedef enum {
	INITIAL,
	WAIT_CONNECTIONS,
	RUN_TEST,
	TEST_FINISHED
} master_state_t;

typedef enum {
	INITIALIZATION,
	BUSSY,
	ERROR,
	FINISHED
} test_state_t;

typedef struct {
	int t_id;
	int* nodes;
	int required_nodes;
	const char* desc;
	test_state_t state;
} test_context_t;

typedef test_state_t (*test_hndl)(test_context_t* desc);

typedef struct {
	test_context_t context;
	test_hndl hndl;
} test_descriptor_t;

test_state_t test1(test_context_t* desc){
	switch(desc->state){
	case INITIALIZATION:{
		desc->state = BUSSY;
		break;
	}
	case BUSSY:{
		desc->state = ERROR;
		break;
	}
	case ERROR:{
		desc->state = FINISHED;
		break;
	}
	case FINISHED:{
		desc->state = FINISHED;
		break;
	}
	}
	printf("%s  state %d\n", __func__, desc->state);
	return desc->state;
}

test_state_t test2(test_context_t* desc){
	switch(desc->state){
	case INITIALIZATION:{
		desc->state = BUSSY;
		break;
	}
	case BUSSY:{
		desc->state = ERROR;
		break;
	}
	case ERROR:{
		desc->state = FINISHED;
		break;
	}
	case FINISHED:{
		desc->state = FINISHED;
		break;
	}
	}
	printf("%s  state %d\n", __func__, desc->state);
	return desc->state;
}

test_state_t test3(test_context_t* desc){
	switch(desc->state){
	case INITIALIZATION:{
		desc->state = BUSSY;
		break;
	}
	case BUSSY:{
		desc->state = ERROR;
		break;
	}
	case ERROR:{
		desc->state = FINISHED;
		break;
	}
	case FINISHED:{
		desc->state = FINISHED;
		break;
	}
	}
	printf("%s  state %d\n", __func__, desc->state);
	return desc->state;
}

test_state_t test4(test_context_t* desc){
	switch(desc->state){
	case INITIALIZATION:{
		desc->state = BUSSY;
		break;
	}
	case BUSSY:{
		desc->state = ERROR;
		break;
	}
	case ERROR:{
		desc->state = FINISHED;
		break;
	}
	case FINISHED:{
		desc->state = FINISHED;
		break;
	}
	}
	printf("%s  state %d\n", __func__, desc->state);
	return desc->state;
}

#define CONTEXT_CREATION
#include"test_cfg.h"

test_descriptor_t test_descs[] = {
#define TEST_DESCRIPTORS
#include"test_cfg.h"
};

void print_macs(struct ether_header* eh ) {
	mac_addr_t mac_d={0};
	mac_addr_t mac_s={0};

	memcpy(mac_d.mac_arrea, eh->ether_dhost, MAC_ADDR_LEN);
	memcpy(mac_s.mac_arrea, eh->ether_shost, MAC_ADDR_LEN);

	printf("d_mac: '%012lx', s_mac:  '%012lx' type '%x' '%s'\n",
			htobe64(mac_d.mac)>>16,
			htobe64(mac_s.mac)>>16,
			htobe16(eh->ether_type),
			protocol_name(htobe16(eh->ether_type))
	);
}

#define INITIAL_TIMEOUT         (100)

int do_sniff(int fd) {
	int rval;
	char buf[6666];
	/* Header structures */
	struct sockaddr_ll rcvaddr;
	struct ether_header *eh = (struct ether_header *) buf;
	socklen_t lens = sizeof(struct sockaddr);
	memset(buf,0,sizeof(buf));
	do	{

		rval = recvfrom(fd,buf,sizeof(buf),0,(struct sockaddr*)&rcvaddr,&lens);
		if(rval < 0)
		{
			if (errno != EWOULDBLOCK)
			{
				perror("  recv() failed");
				fd = -1;
			}
			break;
		}
		printf("LEN=%d ", rval);
		print_macs(eh);

	} while(rval > 0);

	return fd;
}

typedef enum {
   C_IDLE,
   C_ACCEPTED,
   C_CONNECTED,
   C_DISCONNECTED,
   C_CLOSED
} con_status_t;

typedef struct {
	con_status_t status;
	struct addrinfo *add_info;
	void* conn_data;
}connection_ctx_t;

typedef struct {
	connection_ctx_t con[MAX_CONNECTIONS];
	struct pollfd    fds[MAX_CONNECTIONS];
	int nfds;
}master_ctx_t;

master_ctx_t master_ctx;

static void init_master_ctx(master_ctx_t* mctx) {

	if(mctx) {

		int i;
		memset(mctx, 0, sizeof(mctx[0]));
		for(i = 0; i < MAX_CONNECTIONS; i++) {
			mctx->fds[i].fd = 0;
			mctx->fds[i].events = POLLIN;
			mctx->con[i].status = C_IDLE;
		}
	}
}

void test_master (char* eth)
{
	int    len, rc, rc_poll;
	int     new_sd = -1;
	int    end_server = FALSE, compress_array = FALSE;
	int    close_conn;
	char   buffer[80];
	int    timeout;
//	struct pollfd fds[MAX_CONNECTIONS];
	int    current_size = 0, i, j;
	static uint32_t state = INITIAL;
	int test_counter = 0;
	short int old_if_mode;

	init_master_ctx(&master_ctx);
	/* Create an socket to receive incoming connections  (listener)    */
	new_sd = init_socket(NULL, MASTER_PORT, SOCK_STREAM_AF_UNSPEC,
			SOCKET_NON_BLOCKING | SOCKET_BIND);

	if (new_sd < 0)
	{
		perror("socket() failed");
		exit(-1);
	}

	rc = listen(new_sd, 32);
	if (rc < 0)
	{
		perror("listen() failed");
		close(new_sd);
		exit(-1);
	}

	/* Set up the initial listening socket                        */
	master_ctx.fds[master_ctx.nfds].fd = new_sd;
	master_ctx.con[master_ctx.nfds].status = C_CONNECTED;
	master_ctx.nfds++;

	/*Init Raw sniff socket*/
	new_sd = init_socket(NULL, NULL, SOCK_SNIF_ROW_ETH, SOCKET_NON_BLOCKING);

	if (new_sd < 0)
	{
		perror("sniff socket() failed");
		exit(-1);
	}
	old_if_mode = set_promiscuous(eth, &new_sd, TRUE);

	master_ctx.fds[master_ctx.nfds].fd = new_sd;
	master_ctx.con[master_ctx.nfds].status = C_CONNECTED;
	master_ctx.nfds++;
	/* Initialize the timeout*/
	timeout = INITIAL_TIMEOUT;

	/* Loop waiting for incoming connects or for incoming data */
	do
	{
		/* Call poll() with timeout */
		printf("Waiting on poll()...\n");
		rc_poll = poll(master_ctx.fds, master_ctx.nfds, timeout);

		/* Check to see if the poll call failed. */
		if (rc_poll < 0)
		{
			perror("  poll() failed");
			break;
		}

		/* Check to see if the time out expired. */
		if (rc_poll != 0) {

			/* One or more descriptors are readable. Need to          */
			/* determine which ones they are.                          */
			current_size = master_ctx.nfds;
			for (i = 0; i < current_size; i++)
			{
				/* Loop through to find the descriptors that returned    */
				/* POLLIN and determine whether it's the listening       */
				/* or the active connection.                             */
				if(master_ctx.fds[i].revents == 0)
					continue;

				/* If revents is not POLLIN, it's an unexpected result,  */
				/* log and end the server.                               */
				if(master_ctx.fds[i].revents != POLLIN)
				{
					printf("  Error! revents = %d\n", master_ctx.fds[i].revents);
					end_server = TRUE;
					break;

				}

				if (i == LISTENER_FD_IDX) {
					/* Listening descriptor is readable.                   */
					printf("  Listening socket is readable\n");

					/* Accept all incoming connections that are            */
					/* queued up on the listening socket before we         */
					/* loop back and call poll again.                      */
					do
					{
						/* Accept each incoming connection. */
						new_sd = accept(master_ctx.fds[i].fd, NULL, NULL);
						if (new_sd < 0)
						{
							if (errno != EWOULDBLOCK)
							{
								perror("  accept() failed");
								end_server = TRUE;
							}
							break;
						}

						if(master_ctx.nfds >= MAX_CONNECTIONS) {
							perror("Can't  accept() connection: maximum allowed reached");
							close(new_sd);
							continue;
						}

						set_socket_blocking_mode(new_sd, NON_BLOCKING);

						/* Add descriptor to poll*/
						printf("  New incoming connection - %d\n", new_sd);
						master_ctx.fds[master_ctx.nfds].fd = new_sd;
						master_ctx.fds[master_ctx.nfds].events = POLLIN;
						master_ctx.nfds++;

					} while (new_sd != -1);

				} else if (i == SNIFF_FD_IDX) {

					/*Sniff socket processing*/
					if(do_sniff(master_ctx.fds[i].fd) < 0) {
						perror(" Sniffing failed");
						end_server = TRUE;
					}
				}
				/* This is not the listening socket, therefore an        */
				/* existing connection must be readable                  */
				else
				{
					printf("  Descriptor %d is readable\n", master_ctx.fds[i].fd);
					close_conn = FALSE;

					/* Receive all incoming data on this socket            */
					/* before we loop back and call poll again.            */
					do
					{
						/* Receive data on this connection until the         */
						/* recv fails with EWOULDBLOCK. If any other         */
						/* failure occurs, we will close the                 */
						/* connection.                                       */
						rc = recv(master_ctx.fds[i].fd, buffer, sizeof(buffer), 0);
						if (rc < 0)
						{
							if (errno != EWOULDBLOCK)
							{
								perror("  recv() failed");
								close_conn = TRUE;
							}
							break;
						}

						/* Check to see if the connection has been           */
						/* closed by the client                              */
						if (rc == 0)
						{
							printf("  Connection closed\n");
							close_conn = TRUE;
							break;
						}

						/* Data was received                                 */
						len = rc;
						printf("  %d bytes received------------------------------------------------------->\n", len);


						rc = send(master_ctx.fds[i].fd, buffer, len, 0);
						if (rc < 0)
						{
							perror("  send() failed");
							close_conn = TRUE;
							break;
						}

					} while(TRUE);

					/*******************************************************/
					/* If the close_conn flag was turned on, we need       */
					/* to clean up this active connection. This            */
					/* clean up process includes removing the              */
					/* descriptor.                                         */
					/*******************************************************/
					if (close_conn)
					{
						printf("!!! Close connection %d",i);
						close(master_ctx.fds[i].fd);
						master_ctx.fds[i].fd = -1;
						compress_array = TRUE;
					}
				}  /* End of existing connection is readable             */
			} /* End of loop through pollable descriptors              */
		}

		switch(state) {

		case INITIAL: {

			if (test_counter >= sizeof(test_descs)/sizeof(test_descs[0])) {
				printf("All test are executed. End program.\n");
				end_server = TRUE;
			}
			else {
				timeout = 10000;
				if(master_ctx.nfds >= test_descs[test_counter].context.required_nodes) {
					int i;
					//set test context
					for (i=0; i < test_descs[test_counter].context.required_nodes; i++) {
						test_descs[test_counter].context.nodes[i] = master_ctx.fds[i + 1].fd;
					}
					state = RUN_TEST;
				}
				else {
					state = WAIT_CONNECTIONS;
				}
			}
			break;
		}
		case WAIT_CONNECTIONS: {
			if (rc_poll == 0) {
				printf("  poll() timed out in state %d test id %d.  End program.\n",
						state, test_descs[test_counter].context.t_id);
				end_server = TRUE;
				break;
			}
			if(master_ctx.nfds >= test_descs[test_counter].context.required_nodes) {
				int i;
				//set test context
				for (i=0; i < test_descs[test_counter].context.required_nodes; i++) {
					test_descs[test_counter].context.nodes[i] = master_ctx.fds[i + 1].fd;
					//		assert(test_descs[test_counter].context.nodes[i] != -1);
				}
				state = RUN_TEST;
			}
			break;
		}
		case RUN_TEST:{
			if (rc_poll == 0) {
				printf("  poll() timed out in state %d test id %d.  End program.\n",
						state, test_descs[test_counter].context.t_id);
				end_server = TRUE;
				break;
			}
			if( FINISHED == test_descs[test_counter].hndl(&test_descs[test_counter].context) ){
				timeout = INITIAL_TIMEOUT;
				state = TEST_FINISHED;
			}
			break;
		}
		case TEST_FINISHED:{
			state   = INITIAL;
			test_counter++;
			timeout = INITIAL_TIMEOUT;
			break;
		}

		default: {
			printf("Error: Wrong state %d.  End program.\n", state);
			end_server = TRUE;
		}
		}

		printf(" state %d\n", state);

		/* If the compress_array flag was turned on, we need       */
		/* to squeeze together the array and decrement the number  */
		/* of file descriptors. We do not need to move back the    */
		/* events and revents fields because the events will always*/
		/* be POLLIN in this case, and revents is output.          */
		if (compress_array)
		{
			compress_array = FALSE;
			for (i = 0; i < master_ctx.nfds; i++)
			{
				if (master_ctx.fds[i].fd == -1)
				{
					for(j = i; j < master_ctx.nfds; j++)
					{
						master_ctx.fds[j].fd = master_ctx.fds[j+1].fd;
					}
					i--;
					master_ctx.nfds--;
				}
			}
		}

	} while (end_server == FALSE); /* End of serving running.    */

	/*************************************************************
	 * Return old promiscuous mode
	 *************************************************************/
	if(!(old_if_mode & IFF_PROMISC)) {
		set_promiscuous(eth, &master_ctx.fds[SNIFF_FD_IDX].fd, FALSE);
	}
	/*************************************************************/
	/* Clean up all of the sockets that are open                 */
	/*************************************************************/
	for (i = 0; i < master_ctx.nfds; i++)
	{
		if(master_ctx.fds[i].fd >= 0)
			close(master_ctx.fds[i].fd);
	}

}

int main(int argc, char *argv[])
{
	//	Sniff("wlp2s0");//wlp2s0 enp0s25:
	if(argc > 2) {
		test_client();
	}
	else {
		test_master("enp0s25");
	}
	return 0;
}
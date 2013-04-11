/*
** client.c -- a stream socket client demo
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <arpa/inet.h>

#define MAXDATASIZE 100 // max number of bytes we can get at once 

#define INCORRECT_USER		-1
#define INCORRECT_PASS		-2
#define AUTHENTICATION_OK	 0
#define INCORRECT_USER_MSG	"Usuario Inexistente."
#define INCORRECT_PASS_MSG	"Password Erronea."
#define AUTHENTICATION_OK_MSG	"Autenticacion OK."

const char msg_respuesta[3][50] = { INCORRECT_PASS_MSG, INCORRECT_USER_MSG, AUTHENTICATION_OK_MSG };

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}

	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int login(int sockfd, const char* user, const char* pass) {
	int ret, numbytes;
	char buffer[MAXDATASIZE];

	/* Solicitamos la autenticacion */
	sprintf(buffer, "%s\r\n", user);
	send(sockfd, buffer, strlen(buffer), 0);
	sprintf(buffer, "%s\r\n", pass);
	send(sockfd, buffer, strlen(buffer), 0);
//	shutdown(sockfd, SHUT_WR); // TODO: No existe flush! Entonces... no hay
				   // otra manera de solucionar esto sin tener
				   // que cerrar el socket? (y sin quitar nagle!)

	/* Procesamos la respuesta */
	numbytes = recv(sockfd, buffer, MAXDATASIZE, 0);
	if(numbytes == -1) {
		perror("Oh my God 1!! This is an error!");
		exit(1);
	}
	buffer[numbytes] = '\0';    // A~adimos fin de cadena por seguridad
	sscanf(buffer, "%d", &ret); // Aca obtenemos el numero
	if(ret < -2 || ret > 0) {
		perror("Oh my God 2!! This is an error!");
		exit(1);
	}
	
	return ret;
}

int main(int argc, char *argv[])
{
	int sockfd, numbytes, code;  
	char buf[MAXDATASIZE];
	struct addrinfo hints, *servinfo, *p;
	int rv;
	char s[INET6_ADDRSTRLEN];

	if (argc != 5) {
	    fprintf(stderr,"usage: %s <IPserver> <puerto> <user> <passwd>\n",argv[0]);
	    exit(1);
	}

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if ((rv = getaddrinfo(argv[1], argv[2], &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		return 1;
	}

	// loop through all the results and connect to the first we can
	for(p = servinfo; p != NULL; p = p->ai_next) {
		if ((sockfd = socket(p->ai_family, p->ai_socktype,
				p->ai_protocol)) == -1) {
			perror("client: socket");
			continue;
		}

		if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			close(sockfd);
			perror("client: connect");
			continue;
		}

		break;
	}

	if (p == NULL) {
		fprintf(stderr, "client: failed to connect\n");
		return 2;
	}



	freeaddrinfo(servinfo); // all done with this structure

	// Llamo a la funcion que realiza el login
	code = login(sockfd, argv[3], argv[4]);
	
	// Imprimo el resultado del login por pantalla
	inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr),
		s, sizeof s);
	printf("----------------------------------------\n");
	printf("Server: %s\n",s); 
	printf("Usuario:  %s\n",argv[3]);
	printf("Password: %s\n",argv[4]);
	printf("\n%d: %s\n", code, msg_respuesta[code+2]);
	printf("----------------------------------------\n\n");

	close(sockfd);

	return 0;
}


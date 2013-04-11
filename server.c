/*
** server.c -- a stream socket server demo
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>

#define BACKLOG 10	 // how many pending connections queue will hold
#define LENGTH_BUFFER	100
#define MAX_LENGTH_USER		20
#define MAX_LENGTH_PASS		20
#define INCORRECT_USER		-1
#define INCORRECT_PASS		-2
#define AUTHENTICATION_OK	 0
#define INCORRECT_USER_MSG	"Usuario Inexistente."
#define INCORRECT_PASS_MSG	"Password Erronea."
#define AUTHENTICATION_OK_MSG	"Autenticacion OK."

const char msg_respuesta[3][50] = { INCORRECT_PASS_MSG, INCORRECT_USER_MSG, AUTHENTICATION_OK_MSG };

void sigchld_handler(int s)
{
	while(waitpid(-1, NULL, WNOHANG) > 0);
}

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}

	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

/*
 * La funcion login acepta como entrada dos cadenas, usuario y contrase;a,
 * y las compara contra el archivo de usuarios definido en el servidor.
 * 
 * Devuelve un codigo entero:
 *  - INCORRECT_USER: Si el usuario pasado como parametro no esta definido.
 *  - INCORRECT_PASS: Si la contrase;a no se corresponde con la del usuario.
 *  - AUTHENTICATION_OK: Si el usuario y la contrase;a pasan con exito el
 *     proceso de autenticacion.
 */
int login(const char* user, const char* pass) {
	int ret= INCORRECT_USER;
	FILE* fd_auth = fopen("userauth", "r");
	char  buffer[1024];
	char* fuser;
	char* fpass;
	
	memset(buffer, 0, sizeof(buffer));
	while ( fgets ( buffer, sizeof buffer, fd_auth ) != NULL )
	{
		fuser = strtok(buffer, ";");
		fpass = strtok(NULL, "\n");
		
		if(strcmp(user,fuser)!=0) {
			continue;
		}
		if(strcmp(pass,fpass)!=0) {
			ret= INCORRECT_PASS;
			break;
		}
		
		ret= AUTHENTICATION_OK;
		break;	
		
	}
	fclose ( fd_auth );
	
	return ret;
}

/*
 * La funcion obtener lee los datos enviados via el socket pasado como argumento
 * y parsea este flujo para obtener el usuario y la contrase;a que nos envia el
 * cliente.
 */
void obtener(int sockfd, char* user, char* pass) {
	char buffer[LENGTH_BUFFER];
	char* d[2] = { user, pass }; // Apunta a la variable a completar
	char* s; // Apunta a la siguiente caracter a completar de { user, pass }
	int i, j, numbytes, isParse;
	
	j=0;		// 0-> user; 1-> pass; 2-> todo parseado!
	s= d[j];	// Primero lo primero (user)
	numbytes=1;	// Enganio para saltear la primera comprobacion
	isParse=0;	// Flag de corte para while
	while(!isParse) {
		if(numbytes == 0) { // Es decir, esta comprobacion
			perror("server: Faltan datos de conexion");
			exit(1);
		}
		numbytes = recv(sockfd, buffer,LENGTH_BUFFER,0); // RECV!
		if(numbytes < 1) {
			perror("server (receive)");
			exit(1);
		}
		
		/* Se copia la cadena de caracteres desde el buffer a la variable
		 * correspondiente apuntada por d (user o pass).
		 */
		for(i=0; i < numbytes && buffer[i] != '\n'; i++) {
			*s=buffer[i];
			s++; // Posicionamos el puntero en la siguiente posicion
		}

		/* Cuando termina de copiar lo que hay en buffer, verifica si
		 * ya se envio la cadena completa para la variable actual
		 * (user o pass). Si es asi, cierra la cadena en la variable
		 * correspondiente y se pone a trabajar en la siguiente.
		 */
		if(i < numbytes) { // Encontramos un '\n' my friend!
			*s='\0'; // Finalizamos la cadena
			/* Si existe, quitamos el caracter tabulador */
			if(s>d[j] && *(s-1) == '\r') *(s-1) = '\0';
			
			j++; /* Pasamos al siguiente "nivel" (pass) */
			s=d[j];
		}
		if(j>1) isParse=1; // Si ya procesamos las dos var, fin.
	}
}

/* 
 * Esta funcion atiende a cada cliente que establece una conexion con nuestro
 * servidor.
 */
void servir(int thread_fd, const char* s) {
	char user[MAX_LENGTH_USER];
	char pass[MAX_LENGTH_PASS];
	char scode[4];
	int numbytes;
	int code;
	
	obtener(thread_fd, user, pass);
	
//	printf("DEBUG: Resultado del parse: *%s*, *%s*", user, pass);
//	exit(0);
	
	code = login(user, pass);

	// Devolver el valor que corresponda
	sprintf(scode, "%d\n", code);
	if (send(thread_fd, scode, strlen(scode), 0) == -1) {
		perror("send: error al responder al cliente");
		exit(1);
	}
	
	printf("----------------------------------------\n");
	printf("Host: %s\n",s); 
	printf("Usuario:  %s\n",user);
	printf("Password: %s\n",pass);
	printf("\n%d: %s\n", code, msg_respuesta[code+2]);
	printf("----------------------------------------\n\n");
	close(thread_fd);
	
}

int main(int argc, char *argv[])
{
	int sockfd, new_fd;  // listen on sock_fd, new connection on new_fd
	struct addrinfo hints, *servinfo, *p;
	struct sockaddr_storage their_addr; // connector's address information
	socklen_t sin_size;
	struct sigaction sa;
	int yes=1;
	char s[INET6_ADDRSTRLEN];
	int rv;

	/** Manejo de argumentos **********************************************/
	if(argc != 2)
	{
		perror("server: parametros incorrectos");
			exit(1);
	}

	/** Conexion **********************************************************/
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE; // use my IP

	if ((rv = getaddrinfo(NULL, argv[1], &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		return 1;
	}

	// loop through all the results and bind to the first we can
	for(p = servinfo; p != NULL; p = p->ai_next) {
		if ((sockfd = socket(p->ai_family, p->ai_socktype,
				p->ai_protocol)) == -1) {
			perror("server: socket");
			continue;
		}

		if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes,
				sizeof(int)) == -1) {
			perror("setsockopt");
			exit(1);
		}

		if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			close(sockfd);
			perror("server: bind");
			continue;
		}

		break;
	}

	if (p == NULL)  {
		fprintf(stderr, "server: failed to bind\n");
		return 2;
	}

	freeaddrinfo(servinfo); // all done with this structure

	if (listen(sockfd, BACKLOG) == -1) {
		perror("listen");
		exit(1);
	}

	sa.sa_handler = sigchld_handler; // reap all dead processes
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	if (sigaction(SIGCHLD, &sa, NULL) == -1) {
		perror("sigaction");
		exit(1);
	}

	printf("server: esperando conexiones...\n");

	while(1) {  // main accept() loop
		sin_size = sizeof their_addr;
		new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
		if (new_fd == -1) {
			perror("accept");
			continue;
		}

		inet_ntop(their_addr.ss_family,
			get_in_addr((struct sockaddr *)&their_addr),
			s, sizeof s);
		printf("server: obtenida conexion desde: %s\n", s);

		if (!fork()) { // this is the child process
			close(sockfd); // child doesn't need the listener
			servir(new_fd, s);
			close(new_fd);
			exit(0);
		}
		close(new_fd);  // parent doesn't need this
	}

	return 0;
}


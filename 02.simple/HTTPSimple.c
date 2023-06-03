/*
AUTHOR: Abhijeet Rastogi (http://www.google.com/profiles/abhijeet.1989)

This is a very simple HTTP server. Default port is 10000 and ROOT for the server is your current working directory..

You can provide command line arguments like:- $./a.aout -p [port] -r [path]

for ex.
$./a.out -p 50000 -r /home/
to start a server at port 50000 with root directory as "/home"

$./a.out -r /home/shadyabhi
starts the server at port 10000 with ROOT as /home/shadyabhi

*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>
#include <fcntl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define CONNMAX 1000
#define BYTES 1024

char *ROOT;
int listenfd, clients[CONNMAX];
SSL_CTX *ssl_ctx; // Контекст SSL

void error(char *);
void startServer(char *);
void respond(int);

int main(int argc, char *argv[])
{
    struct sockaddr_in clientaddr;
    socklen_t addrlen;
    char c;

    //Default Values PATH = ~/ and PORT=10000
    char PORT[6];
    ROOT = getenv("PWD");
    strcpy(PORT, "10000");

    int slot = 0;

    //Parsing the command line arguments
    while ((c = getopt(argc, argv, "p:r:")) != -1)
    {
        switch (c)
        {
        case 'r':
            ROOT = malloc(strlen(optarg));
            strcpy(ROOT, optarg);
            break;
        case 'p':
            strcpy(PORT, optarg);
            break;
        case '?':
            fprintf(stderr, "Wrong arguments given!!!\n");
            exit(1);
        default:
            exit(1);
        }
    }

    printf("Server started at port no. %s%s%s with root directory as %s%s%s\n", "\033[92m", PORT, "\033[0m", "\033[92m", ROOT, "\033[0m");
    printf("============================================\n");
    printf("\n");

    // Setting all elements to -1: signifies there is no client connected
    int i;
    for (i = 0; i < CONNMAX; i++)
        clients[i] = -1;

    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ssl_ctx = SSL_CTX_new(TLSv1_2_server_method());

    // Загрузка сертификата и приватного ключа
    if (SSL_CTX_use_certificate_file(ssl_ctx, "server.crt", SSL_FILETYPE_PEM) <= 0)
    {
        printf("Ошибка загрузки сертификата.\n");
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, "server.key", SSL_FILETYPE_PEM) <= 0)
    {
        printf("Ошибка загрузки приватного ключа.\n");
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    // Установка поддерживаемых шифров
    SSL_CTX_set_cipher_list(ssl_ctx, "HIGH:!aNULL:!MD5");

    startServer(PORT);

    // ACCEPT connections
    while (1)
    {
        addrlen = sizeof(clientaddr);
        clients[slot] = accept(listenfd, (struct sockaddr *)&clientaddr, &addrlen);

        if (clients[slot] < 0)
            error("accept() error");
        else
        {
            if (fork() == 0)
            {
                respond(slot);
                exit(0);
            }
        }

        while (clients[slot] != -1)
            slot = (slot + 1) % CONNMAX;
    }

    SSL_CTX_free(ssl_ctx); // Освобождение контекста SSL

    return 0;
}

//start server
void startServer(char *port)
{
    struct addrinfo hints, *res, *p;

    // getaddrinfo for host
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    if (getaddrinfo(NULL, port, &hints, &res) != 0)
    {
        perror("getaddrinfo() error");
        exit(1);
    }
    // socket and bind
    for (p = res; p != NULL; p = p->ai_next)
    {
        listenfd = socket(p->ai_family, p->ai_socktype, 0);
        if (listenfd == -1)
            continue;
        if (bind(listenfd, p->ai_addr, p->ai_addrlen) == 0)
            break;
    }
    if (p == NULL)
    {
        perror("socket() or bind()");
        exit(1);
    }

    freeaddrinfo(res);

    // listen for incoming connections
    if (listen(listenfd, 1000000) != 0)
    {
        perror("listen() error");
        exit(1);
    }
}

//client connection
void respond(int n)
{
    char mesg[99999], *reqline[3], data_to_send[BYTES], path[99999];
    int rcvd, fd, bytes_read;

    memset((void *)mesg, (int)'\0', 99999);

    SSL *ssl = SSL_new(ssl_ctx);
    SSL_set_fd(ssl, clients[n]);

    if (SSL_accept(ssl) <= 0)
    {
        printf("Ошибка установки SSL соединения.\n");
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    rcvd = SSL_read(ssl, mesg, 99999);

    if (rcvd < 0) // receive error
        fprintf(stderr, ("recv() error\n"));
    else if (rcvd == 0) // receive socket closed
        fprintf(stderr, "Client disconnected unexpectedly.\n");
    else // message received
    {
        printf("%s", mesg);
        reqline[0] = strtok(mesg, " \t\n");
        if (strncmp(reqline[0], "GET\0", 4) == 0)
        {
            reqline[1] = strtok(NULL, " \t");
            reqline[2] = strtok(NULL, " \t\n");
            if (strncmp(reqline[2], "HTTP/1.0", 8) != 0 && strncmp(reqline[2], "HTTP/1.1", 8) != 0)
            {
                SSL_write(ssl, "HTTP/1.0 400 Bad Request\n", 25);
            }
            else
            {
                if (strncmp(reqline[1], "/\0", 2) == 0)
                    reqline[1] = "/index.html"; //Because if no file is specified, index.html will be opened by default (like it happens in APACHE...

                strcpy(path, ROOT);
                strcpy(&path[strlen(ROOT)], reqline[1]);
                printf("file: %s\n", path);
                printf("============================================\n");
                printf("\n");

                if ((fd = open(path, O_RDONLY)) != -1) //FILE FOUND
                {
                    SSL_write(ssl, "HTTP/1.0 200 OK\n\n", 17);
                    while ((bytes_read = read(fd, data_to_send, BYTES)) > 0)
                        SSL_write(ssl, data_to_send, bytes_read);
                }
                else
                    SSL_write(ssl, "HTTP/1.0 404 Not Found\n", 23); //FILE NOT FOUND
            }
        }
    }

    //Closing SOCKET
    SSL_shutdown(ssl);
    close(clients[n]);
    clients[n] = -1;
}

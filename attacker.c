#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>

int main(void)
{
    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(8888);

    int address_len = sizeof(address);

    int server = socket(AF_INET, SOCK_STREAM, 0);

    bind(server, (struct sockaddr*)&address, address_len);

    int new_socket = accept(server, (struct sockaddr*)&address, (socklen_t*)&address_len);

    char buffer[1024] = {0};

    int message = read(new_socket, buffer, 1024);
    printf("%s\n", buffer);
}
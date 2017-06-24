/**
 * 	OneTimePad 1.0.1
 * 	© Siamak Ahghari
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "oneTimePad.h"


#define THREADS MAX_THREADS

const char* HELP = "--help";
const char* HELP_SHORT = "-h";
const char* ENCRYPT = "--encrypt";
const char* ENCRYPT_SHORT = "-e";
const char* DECRYPT = "--decrypt";
const char* DECRYPT_SHORT = "-d";
const char* ENCPIPE = "--enpipe";
const char* ENCPIPE_SHORT = "-ep";
const char* DECPIPE = "--depipe";
const char* DECPIPE_SHORT = "-dp";
const char* VERSION = "--version";
const char* VERSION_SHORT = "-v";

const char* _VERSION_ = "1.0.1";
const char* STD_KEY_FILENAME = "otpkey.bin";

const short IF_TAG = 0x01;
const short OF_TAG = 0x02;
const short IK_TAG = 0x03;
const short OK_TAG = 0x04;
const short SK_TAG = 0x05;

void help(void) {
	printf("\nUSAGE:\n\nOneTimePad [ACTION] [INPUT FILE] [[KEY FILE]] [OUTPUT FILE]\n\nNote: [KEY FILE] is only mandatory for decryption, if you exclude it\n      for encryption, it will be saved as '%s'!\n\nactions:\n\n-e, --encrypt:     Encrypts the input file and saves it to output file,\n                   key saved as key file or '%s'.\n\n-d, --decrypt:     Decrypts an encrypted input file with the key file\n                   and saves the result as output file.\n\n-ep, --enpipe:     Encrypts stdin input and sends it to stdout,\n                   key saved as key file or '%s'.\n\n-dp, --depipe:     Decrypts the stdin input with the key file\n                   and sends it to stdout.\n\n-v, --version:     Prints the release version of OneTimePad.\n\n-h, --help:        Shows usage information.\n\n", STD_KEY_FILENAME, STD_KEY_FILENAME, STD_KEY_FILENAME);
}

char* errMessage(const short ftag, const char* fpath) {
	char* res;
	if(fpath != NULL)
		res = calloc(0x7F + strlen(fpath), sizeof(char));
	else
		res = calloc(0x7F, sizeof(char));
	switch (ftag) {
	case 0x05:
		strcat(res, "ERROR: Unable to create standard key file in current directory, try again as superuser!");
		break;
	case 0x04:
		strcat(res, "ERROR: Unable to create key file '");
		strcat(res, fpath);
		strcat(res, "' in current directory, try again as superuser!");
		break;
	case 0x03:
		strcat(res, "ERROR: Key file '");
		strcat(res, fpath);
		strcat(res, "' does not exist or is not accessible!");
		break;
	case 0x02:
		strcat(res, "ERROR: Unable to create output file '");
		strcat(res, fpath);
		strcat(res, "', try again as superuser!");
		break;
	case 0x01:
		strcat(res, "ERROR: Input file '");
		strcat(res, fpath);
		strcat(res, "' does not exist or is not accessible!");
		break;
	}
	return res;
}


int main(int argc, char* argv[])
{
	FILE *fi, *fo, *ko;
	if (argc > 1) {
		switch (argc) {
		case 2:
			if (strcmp(argv[1], HELP) == 0 || strcmp(argv[1], HELP_SHORT) == 0) {
				help();
				return EXIT_SUCCESS;
			}
			else if (strcmp(argv[1], VERSION) == 0 || strcmp(argv[1], VERSION_SHORT) == 0) {
				printf("%s", _VERSION_);
				printf("\n");
				return EXIT_SUCCESS;
			}
			else if (strcmp(argv[1], ENCPIPE) == 0 || strcmp(argv[1], ENCPIPE_SHORT) == 0) {
				printf("\n");
				if ((ko = fopen(STD_KEY_FILENAME, WRITE)) != NULL) {
					pencrypt(ko);
					fclose(ko);
					printf("\n\n");
					return EXIT_SUCCESS;
				}
				else {
					char* err = errMessage(SK_TAG, NULL);
					printf("%s", err);
					printf("\n\n");
					free(err);
					return EXIT_FAILURE;
				}
			}
			break;
		case 3:
			if (strcmp(argv[1], ENCPIPE) == 0 || strcmp(argv[1], ENCPIPE_SHORT) == 0) {
				printf("\n");
				if ((ko = fopen(argv[2], WRITE)) != NULL) {
					pencrypt(ko);
					fclose(ko);
					printf("\n\n");
					return EXIT_SUCCESS;
				}
				else {
					char* err = errMessage(OK_TAG, argv[2]);
					printf("%s", err);
					printf("\n\n");
					free(err);
					return EXIT_FAILURE;
				}
			}
			else if (strcmp(argv[1], DECPIPE) == 0 || strcmp(argv[1], DECPIPE_SHORT) == 0) {
				printf("\n");
				if ((ko = fopen(argv[2], READ)) != NULL) {
					pdecrypt(ko);
					fclose(ko);
					printf("\n\n");
					return EXIT_SUCCESS;
				}
				else {
					char* err = errMessage(IK_TAG, argv[2]);
					printf("%s", err);
					printf("\n\n");
					free(err);
					return EXIT_FAILURE;
				}
			}
			break;
		case 4:
			if (strcmp(argv[1], ENCRYPT) == 0 || strcmp(argv[1], ENCRYPT_SHORT) == 0) {
				fi = fopen(argv[2], READ);
				if (fi == NULL) {
					char* err = errMessage(IF_TAG, argv[2]);
					printf("%s", err);
					printf("\n\n");
					free(err);
					return EXIT_FAILURE;
				}
				fo = fopen(argv[3], WRITE);
				if (fo == NULL) {
					char* err = errMessage(OF_TAG, argv[3]);
					printf("%s", err);
					printf("\n\n");
					fclose(fi);
					free(err);
					return EXIT_FAILURE;
				}
				ko = fopen(STD_KEY_FILENAME, WRITE);
				if (ko == NULL) {
					char* err = errMessage(SK_TAG, NULL);
					printf("%s", err);
					printf("\n\n");
					fclose(fi);
					fclose(fo);
					free(err);
					return EXIT_FAILURE;
				}
				fclose(fi);
				fclose(fo);
				fclose(ko);
				printf("\nEncrypting......");
				fflush(stdout);
				if (fencrypt_m((unsigned short)THREADS, argv[2], argv[3], STD_KEY_FILENAME)) {
					printf("done\n");
					printf("\nFile '%s' successfully encrypted to '%s'!\n", argv[2], argv[3]);
					printf("Generated key saved in file '%s'\n\n", STD_KEY_FILENAME);
					return EXIT_SUCCESS;
				}
				else {
					printf("failed!\n\n");
					return EXIT_FAILURE;
				}
			}
			break;
		case 5:
			if (strcmp(argv[1], ENCRYPT) == 0 || strcmp(argv[1], ENCRYPT_SHORT) == 0) {
				fi = fopen(argv[2], READ);
				if (fi == NULL) {
					char* err = errMessage(IF_TAG, argv[2]);
					printf("%s", err);
					printf("\n\n");
					free(err);
					return EXIT_FAILURE;
				}
				fo = fopen(argv[4], WRITE);
				if (fo == NULL) {
					char* err = errMessage(OF_TAG, argv[4]);
					printf("%s", err);
					printf("\n\n");
					fclose(fi);
					free(err);
					return EXIT_FAILURE;
				}
				ko = fopen(argv[3], WRITE);
				if (ko == NULL) {
					char* err = errMessage(OK_TAG, argv[3]);
					printf("%s", err);
					printf("\n\n");
					fclose(fi);
					fclose(fo);
					free(err);
					return EXIT_FAILURE;
				}
				fclose(fi);
				fclose(fo);
				fclose(ko);
				printf("\nEncrypting......");
				fflush(stdout);
				if (fencrypt_m((unsigned short)THREADS, argv[2], argv[4], argv[3])) {
					printf("done\n");
					printf("\nFile '%s' successfully encrypted to '%s'!\n", argv[2], argv[4]);
					printf("Generated key saved in file '%s'\n\n", argv[3]);
					return EXIT_SUCCESS;
				}
				else {
					printf("failed!\n\n");
					return EXIT_FAILURE;
				}
			}
			else if (strcmp(argv[1], DECRYPT) == 0 || strcmp(argv[1], DECRYPT_SHORT) == 0) {
				fi = fopen(argv[2], READ);
				if (fi == NULL) {
					char* err = errMessage(IF_TAG, argv[2]);
					printf("%s", err);
					printf("\n\n");
					free(err);
					return EXIT_FAILURE;
				}
				ko = fopen(argv[3], READ);
				if (ko == NULL) {
					char* err = errMessage(IK_TAG, argv[3]);
					printf("%s", err);
					printf("\n\n");
					fclose(fi);
					free(err);
					return EXIT_FAILURE;
				}
				fo = fopen(argv[4], WRITE);
				if (fo == NULL) {
					char* err = errMessage(OF_TAG, argv[4]);
					printf("%s", err);
					printf("\n\n");
					fclose(fi);
					fclose(ko);
					free(err);
					return EXIT_FAILURE;
				}
				fclose(fi);
				fclose(ko);
				fclose(fo);
				printf("\nDecrypting......");
				fflush(stdout);
				if (fdecrypt_m((unsigned short)THREADS, argv[2], argv[3], argv[4])) {
					printf("done\n");
					printf("\nFile '%s' successfully decrypted to '%s'!\n\n", argv[2], argv[4]);
					return EXIT_SUCCESS;
				}
				else {
					printf("failed!\n\n");
					return EXIT_FAILURE;
				}
			}
			break;
		}
	}
	printf("\nERROR: Invalid parameter input!\n\nType -h for help\n\n");
	return EXIT_FAILURE;
}

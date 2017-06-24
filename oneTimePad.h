#ifndef ONETIMEPAD_H
#define ONETIMEPAD_H

#include <stdio.h>
#include <stdlib.h>

// Windows
#if defined(_WIN32)
#include <io.h>
#include <stdint.h>
#include <windows.h>
#define SEEK(_if,offset,origin) _fseeki64((_if),(offset),(origin))
#define TELL(_if) _ftelli64((_if))
#define OFF_T __int64
#define SIZE_T DWORD
#define fsync(fid) _commit((fid))
#define FRETURN DWORD WINAPI
#define FPARAM LPVOID
#define WINDOWS

// MacOS, Linux or any other POSIX-OSes
#elif defined(__linux__) || defined(__linux) || defined(linux) || defined(__APPLE__) || defined(_POSIX_VERSION)
#include <unistd.h>
#include <pthread.h>
#define SEEK(_if,offset,origin) fseeko((_if),(offset),(origin))
#define TELL(_if) ftello((_if))
#define OFF_T off_t
#define SIZE_T size_t
#define FRETURN void*
#define FPARAM void*
#define POSIX

#else
#error "FATAL: Compiler not supported!"
#endif

#include <time.h>
#include <string.h>

#define READ "rb"
#define WRITE "wb"
#define MULTITHREADING_LOWER_BORDER 0x4000000ULL
#define MAX_THREADS 16

typedef struct __buffer__ {
    unsigned char *data;
    unsigned char *key;
	SIZE_T size;
	OFF_T offset;
} buffer;


//Encryption

/**
	Singlethreaded otp-encryption 
*/
int fencrypt(FILE* _fi, FILE* _fo, FILE* _ko);
/**
	Multithreaded otp-encryption
*/
int fencrypt_m(unsigned short threads, const char* _fi, const char* _fo, const char* _ko);
/**
	Singlethreaded otp-encryption using stdin as input and stdout as output
*/
int pencrypt(FILE* _ko);


//Decryption

/**
	Singlethreaded otp-decryption
*/
int fdecrypt(FILE* _fi, FILE* _fo, FILE* _ki);
/**
	Multithreaded otp-decryption
*/
int fdecrypt_m(unsigned short threads, const char* _fi, const char* _ki, const char* _fo);
/**
	Singlethreaded otp-decryption using stdin as input and stdout as output
*/
int pdecrypt(FILE* _ki);

#endif // ONETIMEPAD_H

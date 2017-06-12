#include "oneTimePad.h"

volatile buffer* cache;

typedef struct __arg {
	OFF_T offset;
	SIZE_T size;
} arg;

static void __fbuf(FILE *_fi) {
	for (int k = 0; k < (int)cache->size; k++) {
		cache->data[k] = (unsigned char)fgetc(_fi);
	}
}

static void __kbuf(FILE *_ki) {
	for (int k = 0; k < (int)cache->size; k++)
		cache->key[k] = (unsigned char)fgetc(_ki);
}

FRETURN fencrypt_mp(FPARAM args) {
	arg* a = (arg*)args;
	int c, k;
	OFF_T o = a->offset;
	while (o < (a->offset + (OFF_T)a->size)) {
		k = (rand() % 0x100);
		c = (int)cache->data[(int)o];
		c += k;
		c %= 0x100;
		cache->data[(int)o] = (unsigned char)c;
		cache->key[(int)o] = (unsigned char)k;
		o++;
	}
	return NULL;
}

FRETURN fdecrypt_mp(FPARAM args) {
	arg* a = (arg*)args;
	OFF_T o = a->offset;
	int c, k, u;
	while (o < (a->offset + (OFF_T)a->size)) {
		k = (int)cache->key[(int)o];
		c = (int)cache->data[(int)o];
		// u+k % 256 = c => u+k = n*256 + c, 0≤n≤1 <=> u = n*256 + (c-k)
		// => k>c : n=1, k<=c : n=0
		if (k > c)
			u = (c - k) + 0x100;
		else
			u = c - k;
		cache->data[(int)o] = (unsigned char)u;
		o++;
	}
	return NULL;
}

int fencrypt(FILE* _fi, FILE* _fo, FILE* _ko) {
    if (_fi == NULL || _fo == NULL || _ko == NULL)
        return 0;
    srand((unsigned int)time(NULL));
    int c, k;
    while ((c = fgetc(_fi)) != EOF) {
        k = (rand() % 0x100);
        c += k;
        c %= 0x100;
        fputc(c, _fo);
        fputc(k, _ko);
    }
    return 1;
}

int fencrypt_m(unsigned short threads, const char* _fi, const char* _fo, const char* _ko) {
	if (_fi == NULL || _fo == NULL || _ko == NULL)
		return 0;
	FILE *__fi = fopen(_fi, READ), *__fo = fopen(_fo, WRITE), *__ko = fopen(_ko, WRITE);
	if (__fi == NULL || __fo == NULL || __ko == NULL)
		return 0;
	OFF_T fi_sz;
	SEEK(__fi, 0ULL, SEEK_END);
	fi_sz = TELL(__fi);
	SEEK(__fi, 0ULL, SEEK_SET);
	srand((unsigned int)time(NULL));
	if (threads <= 1 || fi_sz < MULTITHREADING_LOWER_BORDER)
		return fencrypt(__fi, __fo, __ko);
	if (threads > MAX_THREADS)
		threads = MAX_THREADS;
	cache = (buffer*)malloc(sizeof(buffer));
	cache->offset = (OFF_T)0;
	cache->size = (SIZE_T)MULTITHREADING_LOWER_BORDER;
	SIZE_T lsz = (SIZE_T)(fi_sz%MULTITHREADING_LOWER_BORDER);
	int iter = (int)(fi_sz / cache->size), i = 0;
	cache->data = calloc(cache->size, sizeof(unsigned char));
	cache->key = calloc(cache->size, sizeof(unsigned char));
	while (i < iter) {
		fread(cache->data, sizeof(unsigned char), cache->size, __fi);
		OFF_T lo = (OFF_T)0;
		SIZE_T s = (SIZE_T)(MULTITHREADING_LOWER_BORDER / threads);
#ifdef POSIX
		pthread_t thrds[threads];
		arg* args[threads];
#endif
#ifdef WINDOWS
		HANDLE thrds[MAX_THREADS];
		arg* args[MAX_THREADS];
#endif
		for (int k = 0; k < threads; k++) {
			args[k] = (arg*)malloc(sizeof(arg));
			args[k]->offset = lo;
			args[k]->size = s;
#ifdef POSIX
			pthread_create(&thrds[k], NULL, fencrypt_mp, (void*)args[k]);
#endif
#ifdef WINDOWS
			thrds[k] = CreateThread(NULL, 0, &fencrypt_mp, args[k], 0, NULL);
#endif
			lo = lo + (OFF_T)s;
		}
#ifdef POSIX
		for (int k = 0; k < threads; k++) {
			if (pthread_join(thrds[k], NULL)) {
				printf("\nFATAL: Join of worker thread %i unsuccessful, encryption failed!\n", k);
				return 0;
			}
		}
#endif
#ifdef WINDOWS
		DWORD res = WaitForMultipleObjects((DWORD)threads, &thrds, TRUE, INFINITE);
		if (res != WAIT_OBJECT_0) {
			printf("\nFATAL: One or more worker thread(s) unsuccessful, encryption failed!\n ");
		}
#endif
		fwrite(cache->data, sizeof(unsigned char), cache->size, __fo);
		fwrite(cache->key, sizeof(unsigned char), cache->size, __ko);
		cache->offset = cache->offset + (OFF_T)cache->size;
		i++;
	}
	if (lsz > 0) {
		cache->offset = cache->offset - (OFF_T)cache->size;
		cache->size = lsz;
		cache->data = realloc(cache->data, lsz);
		cache->key = realloc(cache->key, lsz);
		fread(cache->data, sizeof(unsigned char), cache->size, __fi);
		int c, k;
		OFF_T o = (OFF_T)0;
		while (o < (OFF_T)lsz) {
			c = (int)cache->data[(int)o];
			k = (rand() % 0x100);
			c += k;
			c %= 0x100;
			cache->data[(int)o] = (unsigned char)c;
			cache->key[(int)o] = (unsigned char)k;
			o++;
		}
		fwrite(cache->data, sizeof(unsigned char), cache->size, __fo);
		fwrite(cache->data, sizeof(unsigned char), cache->size, __ko);
	}
	fclose(__fi);
	fclose(__fo);
	fclose(__ko);
	free(cache->data);
	free(cache->key);
	free(cache);
	return 1;
}

int pencrypt(FILE* _ko) {
    if (_ko == NULL)
        return 0;
    srand((unsigned int)time(NULL));
    int c, k;
    while (read(0, &c, 1) == 1) {
        k = (rand() % 0x100);
        c += k;
        c %= 0x100;
        write(1, &c, 1);
        fputc(k, _ko);
        fsync(1);
    }
    return 1;
}

int fdecrypt(FILE* _fi, FILE* _fo, FILE* _ki) {
    if (_fi == NULL || _fo == NULL || _ki == NULL)
        return 0;
    OFF_T fi_sz, ki_sz;
    SEEK(_fi, 0ULL, SEEK_END);
    fi_sz = TELL(_fi);
    SEEK(_fi, 0ULL, SEEK_SET);
    SEEK(_ki, 0ULL, SEEK_END);
    ki_sz = TELL(_ki);
    SEEK(_ki, 0ULL, SEEK_SET);
    SEEK(_fo, 0ULL, SEEK_SET);
    if (fi_sz == ki_sz) {
        // u+k % 256 = c => u+k = n*256 + c, 0≤n≤1 <=> u = n*256 + (c-k)
        // => k>c : n=1, k<=c : n=0
        int c, k, u;
        while ((c = fgetc(_fi)) != EOF && (k = fgetc(_ki)) != EOF) {
            if (k > c)
                u = (c - k) + 0x100;
            else
                u = c - k;
            fputc(u, _fo);
        }
    }
    else {
        printf("\nFATAL: Wrong key! Size of key file (%lld Byte) is different than the size of input file to decrypt (%lld Byte)!\n\n", ki_sz, fi_sz);
        return 0;
    }
    return 1;
}

int fdecrypt_m(unsigned short threads, const char* _fi, const char* _ki, const char* _fo) {
	if (_fi == NULL || _fo == NULL || _ki == NULL)
		return 0;
	FILE *__fi = fopen(_fi, READ), *__fo = fopen(_fo, WRITE), *__ki = fopen(_ki, READ);
	if (__fi == NULL || __fo == NULL || __ki == NULL)
		return 0;
	OFF_T fi_sz, ki_sz;
	SEEK(__fi, 0ULL, SEEK_END);
	fi_sz = TELL(__fi);
	SEEK(__fi, 0ULL, SEEK_SET);
	if (threads <= 1 || fi_sz < (SIZE_T)MULTITHREADING_LOWER_BORDER)
		return fdecrypt(__fi, __fo, __ki);
	if (threads > MAX_THREADS)
		threads = MAX_THREADS;
	SEEK(__ki, 0ULL, SEEK_END);
	ki_sz = TELL(__ki);
	SEEK(__ki, 0ULL, SEEK_SET);
	SEEK(__fo, 0ULL, SEEK_SET);
	if (fi_sz == ki_sz) {
		cache = (buffer*)malloc(sizeof(buffer));
		cache->offset = (OFF_T)0;
		cache->size = (SIZE_T)MULTITHREADING_LOWER_BORDER;
		SIZE_T lsz = (SIZE_T)(fi_sz%cache->size);
		int iter = (int)(fi_sz / cache->size), i = 0;
		cache->data = calloc(cache->size, sizeof(unsigned char));
		cache->key = calloc(cache->size, sizeof(unsigned char));
		while (i < iter) {
			fread(cache->data, sizeof(unsigned char), cache->size, __fi);
			fread(cache->key, sizeof(unsigned char), cache->size, __ki);
			OFF_T lo = (OFF_T)0;
			SIZE_T s = (SIZE_T)(cache->size / threads);
#ifdef POSIX
			pthread_t thrds[threads];
			arg* args[threads];
#endif
#ifdef WINDOWS
			HANDLE thrds[MAX_THREADS];
			arg* args[MAX_THREADS];
#endif
			for (unsigned short k = 0; k < threads; k++) {
				args[k] = (arg*)malloc(sizeof(arg));
				args[k]->offset = lo;
				args[k]->size = s;
#ifdef POSIX
				pthread_create(&thrds[k], NULL, fdecrypt_mp, args[k]);
#endif
#ifdef WINDOWS
				thrds[k] = CreateThread(NULL, 0, &fdecrypt_mp, args[k], 0, NULL);
#endif
				lo = lo + (OFF_T)s;
			}
#ifdef POSIX
			for (int k = 0; k < threads; k++) {
				if (pthread_join(thrds[k], NULL)) {
					printf("\nFATAL: Join of worker thread %i unsuccessful, decryption failed!\n", k);
					return 0;
				}
			}
#endif
#ifdef WINDOWS
			DWORD res = WaitForMultipleObjects((DWORD)threads, &thrds, TRUE, INFINITE);
			if (res != WAIT_OBJECT_0) {
				printf("\nFATAL: One or more worker thread(s) unsuccessful, decryption failed!\n ");
			}
#endif
			fwrite(cache->data, sizeof(unsigned char), cache->size, __fo);
			cache->offset = cache->offset + (OFF_T)cache->size;
			i++;
		}
		if (lsz > (SIZE_T)0) {
			cache->offset = cache->offset - (OFF_T)cache->size;
			cache->size = lsz;
			cache->data = realloc(cache->data, lsz);
			cache->key = realloc(cache->key, lsz);
			fread(cache->data, sizeof(unsigned char), cache->size, __fi);
			fread(cache->key, sizeof(unsigned char), cache->size, __ki);
			int c, k, u;
			OFF_T o = (OFF_T)0;
			while (o < (OFF_T)cache->size) {
				k = (int)cache->key[(int)o];
				c = (int)cache->data[(int)o];
				if (k > c)
					u = (c - k) + 0x100;
				else
					u = c - k;
				cache->data[(int)o] = (unsigned char)u;
				o++;
			}
			fwrite(cache->data, sizeof(unsigned char), cache->size, __fo);
		}
		fclose(__fi);
		fclose(__fo);
		fclose(__ki);
		free(cache->data);
		free(cache->key);
		free(cache);
	}
	else {
		printf("\nFATAL: Wrong key! Size of key file (%lld Byte) is different than the size of input file to decrypt (%lld Byte)!\n\n", ki_sz, fi_sz);
		return 0;
	}
	return 1;
}

int pdecrypt(FILE* _ki) {
    if (_ki == NULL)
        return 0;
    int c, k, u;
    while ((k = fgetc(_ki)) != EOF) {
        if (read(0, &c, 1) != 1)
            break;
        if (k > c)
            u = (c - k) + 0x100;
        else
            u = c - k;
        write(1, &u, 1);
        fsync(1);
    }
    return 1;
}




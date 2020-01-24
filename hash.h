#ifndef _HASH_H
#define _HASH_H

typedef struct _THASH * HHASH;

typedef void *(*TEventFreeObject) (void *lpvParam, void *lpvObject);

/**
  * Creates a new hash handle
  * @param iHashTableSize optional hash table size. If zero, it will use the
  * default value
  * @return the newly created handle, to be used with the other functions.
  */
HHASH hashNew (int iHashTableSize);

/**
  * Frees the resources related with the given handle, which was previously 
  * created with hashNew.
  * 
  * @param hHash handle which was returned previously by hashNew()
  */
HHASH hashFree (HHASH hHash);

HHASH hashFreeEx(HHASH hHash, TEventFreeObject ptrFreeObjectFunction, void *lpvParam);

void hashClear (HHASH hHash);
void hashClearEx (HHASH hHash, TEventFreeObject ptrFreeObjectFunction, void *lpvParam);

int hashSet (HHASH hHash, char *lpcChave, char *lpcValor);
int hashSetBinary(HHASH hHash, char *lpcChave, char *lpcValor, int length, int flgCount);
int hashSetCpy (HHASH hHash, char *lpcChave, char *lpcValor);
int hashSetCat (HHASH hHhash, char *lpcChave, char *lpcValor, char cSeparador);
int hashSetInt (HHASH hhash, char *lpcChave, int iValor);

void hashSetHashFunction (HHASH hHash, unsigned int (*ptrFuncaoHash) (char *s, const int iPrime));

char *hashGet (HHASH hHash, char *lpcChave);
char *hashGetAsBinary (HHASH hHash, char *lpcChave, int *lpiTamanho, int *lpiCopia);
int hashGetAsInt (HHASH hHash, char *lpcChave);
int hashGetAsIntDef (HHASH hHash, char *lpcChave, int iValorPadrao);

char *hashGetNextKey (HHASH hHash, char *lpcChave);
int hashRemoveKey (HHASH hHash, char *lpcChave);
int hashRenameKey (HHASH hHash, char *lpcChaveOrigem, char *lpcChaveDestino);

#define BASE_HASH                      -0x00003000
#define HASH_ERROR_MEMORY_UNAVAILABLE   BASE_HASH - 1
#define HASH_ERROR_INVALID_HANDLE       BASE_HASH - 2
#define HASH_ERROR_INVALID_PARAMETERS   BASE_HASH - 3

#endif

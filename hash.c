#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hash.h"

#define MAX_TAM_HASH 9929
#define MAX_TAM_KEY  1024
typedef unsigned int (*ptrHashFunction)(char *, int);

typedef struct _THashItem
{
	unsigned char flgCpy;	 // 1, if value contains a copy, and can be freed upon clear/free; 0 otherwise.
	short size;				 // Value size, in bytes
	char *key;				 // Entry key
	char *value;			 // Entry value
	struct _THashItem *next; // Pointer to next collision element
} THashItem;

typedef struct _THASH
{
	THashItem *cache;			  // Cache points to latest accessed element
	THashItem *table;			  // Hash table, with iSize elements
	int iSize;					  // Hash table size
	ptrHashFunction hashFunction; // Pointer to hash function.
} THash;

static int hashCompare(const char *lpcString1, const char *lpcString2)
{
	return strcmp(lpcString1, lpcString2);
}

static unsigned int hashFunction(char *s, const int prime)
{
	unsigned int resp;
	for (resp = s[0], s++; s[0]; s++)
		resp = resp ^ (s[0] * 3);
	return (unsigned int)resp % prime;
}

char *hashGetAsBinary(THash *hHash, char *lpcKey, int *lpiSize, int *lpiCopy)
{
	int h;
	THashItem *cur;
	char caKey[MAX_TAM_KEY];

	if (hHash && lpcKey)
	{
		strncpy(caKey, lpcKey, sizeof(caKey) - 1);
		caKey[sizeof(caKey) - 1] = 0;
		h = hHash->hashFunction(caKey, hHash->iSize);
		cur = hHash->table[h].next;
		while (cur)
		{
			if (!hashCompare(cur->key, caKey))
			{
				if (lpiSize)
					*lpiSize = cur->size;
				if (lpiCopy)
					*lpiCopy = cur->flgCpy;
				return cur->value;
			}
			cur = cur->next;
		}
	}
	return NULL;
}

char *hashGet(THash *hHash, char *lpcKey)
{
	return hashGetAsBinary(hHash, lpcKey, NULL, NULL);
}

static int strStrToInt (const char *lpcValue)
{
  return atoi (lpcValue);
}

static int strToIntDef (char *s, int iDefaultValue)
{
  int iFlgZero;
  int iResult = 0;
  char *ptr;

  iResult = iDefaultValue;
  if (s && strlen (s))
  {
    // Look for a number but zero
    iFlgZero = 1;
    for (ptr = s; *ptr; ptr++)
      if (!(*ptr == '0' || *ptr == ' ' || *ptr == '.' || *ptr == '+' || *ptr == '-'))
      {
        iFlgZero = 0;
        break;
      }
    
    iResult = strStrToInt (s);
    if (!iResult && !iFlgZero)
      iResult = iDefaultValue;
  }
  return iResult;
}

int hashGetAsIntDef(THash *hHash, char *lpcKey, int iDefaultValue)
{
	return strToIntDef(hashGet(hHash, lpcKey), iDefaultValue);
}

int hashGetAsInt(THash *hHash, char *lpcKey)
{
	return strToIntDef(hashGet(hHash, lpcKey), 0);
}

int hashSetBinary(THash *hHash, char *lpcKey, char *lpcValue, int iValueSize, int iFlgCpy)
{
	int h;
	THashItem *cur;
	char caKey[MAX_TAM_KEY];

	if (!hHash)
		return HASH_ERROR_INVALID_HANDLE;

	memset(caKey, 0, sizeof(caKey));
	strncpy(caKey, lpcKey, sizeof(caKey)-1);

	h = hHash->hashFunction(caKey, hHash->iSize);
	for (cur = hHash->table[h].next; cur; cur = cur->next)
		if (!hashCompare(cur->key, caKey))
			break;
	if (!cur)
	{
		cur = malloc(sizeof(THashItem));
		if (!cur)
			return HASH_ERROR_MEMORY_UNAVAILABLE;
		memset(cur, 0, sizeof(sizeof(THashItem)));
		// Insert at the beginning:
		cur->next = hHash->table[h].next;
		hHash->table[h].next = cur;

		cur->key = malloc(strlen(caKey) + 1);
		if (!cur->key)
			return HASH_ERROR_MEMORY_UNAVAILABLE;
		strcpy(cur->key, caKey);
		cur->value = NULL;
	}
	//  cur->type = 0;
	cur->size = iValueSize;
	if (iFlgCpy)
	{
		// Also includes \0
		if (!cur->flgCpy)
			cur->value = malloc(iValueSize + 1);
		else
			cur->value = realloc(cur->value, iValueSize + 1);
		if (!cur->value)
			return HASH_ERROR_MEMORY_UNAVAILABLE;

		if (lpcValue)
		{
			memcpy(cur->value, lpcValue, iValueSize);
			cur->value[iValueSize] = 0;
		}
		else
			memset(cur->value, 0, iValueSize);
	}
	else
	{
		if (cur->flgCpy && cur->value)
		{   // Previous value was a copy, free it
			free(cur->value);
		}

		cur->value = lpcValue;
	}
	cur->flgCpy = iFlgCpy;
	return 0;
}

int hashRenameKey(THash *hHash, char *lpcSourceKey, char *lpcTargetKey)
{
	int iDataSize;
	int iFlgCopy;
	int iResult;
	char *lpcData;

	iResult = HASH_ERROR_INVALID_PARAMETERS;
	if (hHash != NULL && lpcSourceKey != NULL && lpcTargetKey != NULL)
	{
		if (strcmp(lpcSourceKey, lpcTargetKey) == 0)
		{
			// Nothing to do
			iResult = 0;
		}
		else
		{
			lpcData = hashGetAsBinary(hHash, lpcSourceKey, &iDataSize, &iFlgCopy);
			if (lpcData)
			{
				hashSetBinary(hHash, lpcTargetKey, lpcData, iDataSize, iFlgCopy);
				hashRemoveKey(hHash, lpcSourceKey);
				iResult = 0;
			}
		}
	}
	return iResult;
}

int hashSetInt(THash *hash, char *lpcKey, int iValue)
{
	char v[32];

	sprintf(v, "%d%c", iValue, 0);
	return hashSetBinary(hash, lpcKey, v, strlen(v) + 1, 1);
}

int hashSet(THash *hash, char *lpcKey, char *lpcValue)
{
	int iValueSize = 0;

	if (lpcValue)
		iValueSize = strlen(lpcValue) + 1;
	return hashSetBinary(hash, lpcKey, lpcValue, iValueSize, 0);
}

int hashSetCpy(THash *hash, char *lpcKey, char *lpcValue)
{
	int iValueSize = 0;

	if (lpcValue)
		iValueSize = strlen(lpcValue) + 1;
	return hashSetBinary(hash, lpcKey, lpcValue, iValueSize, 1);
}

int hashSetCat(THash *hash, char *lpcKey, char *lpcValue, char cSeparator)
{
	int iRet = 0;
	int iDataSize = 0;
	char *lpcAux = NULL;
	char *lpcMemAloc = NULL;
	char *lpcData = NULL;
	char *lpcDataSaved = NULL;

	if (lpcValue == NULL)
	{
		return (HASH_ERROR_INVALID_PARAMETERS);
	}

	lpcData = lpcValue;

	iDataSize = strlen(lpcData) + 1;

	lpcDataSaved = hashGet(hash, lpcKey);

	if (lpcDataSaved != NULL && strlen(lpcDataSaved) > 0)
	{
		// +1 considering cSeparator
		iDataSize += strlen(lpcDataSaved) + 1;

		lpcMemAloc = malloc(iDataSize);

		if (lpcMemAloc != NULL)
		{
			memset(lpcMemAloc, 0, iDataSize);

			strcpy(lpcMemAloc, lpcDataSaved);

			if (cSeparator > 0)
			{
				lpcAux = lpcMemAloc + strlen(lpcMemAloc) - 1;

				if (*lpcAux != cSeparator)
				{
					lpcAux++;

					*lpcAux = cSeparator;
				}
			}

			strcat(lpcMemAloc, lpcData);

			lpcData = lpcMemAloc;
		}
		else
		{
			return (HASH_ERROR_MEMORY_UNAVAILABLE);
		}
	}

	iRet = hashSetBinary(hash, lpcKey, lpcData, iDataSize, 1);

	if (lpcMemAloc)
	{
		free(lpcMemAloc);
	}

	return (iRet);
}

int hashRemoveKey(THash *hHash, char *lpcKey)
{
	int h;
	THashItem *cur, *ant;
	char caKey[MAX_TAM_KEY];

	if (!hHash)
		return -1;

	strcpy(caKey, lpcKey);

	h = hHash->hashFunction(caKey, hHash->iSize);

	ant = &hHash->table[h];
	cur = hHash->table[h].next;

	while (cur)
	{
		if (!hashCompare(cur->key, caKey))
		{
			ant->next = cur->next;
			free(cur->key);
			if (cur->flgCpy && cur->value)
			{
				free(cur->value);
			}

			free(cur);

			return 0;
		}
		ant = cur;
		cur = cur->next;
	}
	return -2;
}

HHASH hashNew(int iHashTableSize)
{
	THash *hash;
	int i;

	if (!iHashTableSize)
		iHashTableSize = MAX_TAM_HASH;

	hash = malloc(sizeof(THash));
	if (hash)
	{
		memset(hash, 0, sizeof(sizeof(THash)));
		hash->hashFunction = hashFunction;
		hash->cache = NULL;
		hash->table = malloc(iHashTableSize * sizeof(THashItem));
		if (!hash->table)
		{
			free(hash);
			return NULL;
		}
		memset(hash->table, 0, iHashTableSize * sizeof(THashItem));
		hash->iSize = iHashTableSize;

		for (i = 0; i < iHashTableSize; i++)
			hash->table[i].next = NULL;
	}
	return hash;
}

void hashClear(THash *hHash)
{
	hashClearEx(hHash, NULL, NULL);
}

void hashClearEx(THash *hHash, TEventFreeObject ptrFreeObjectFunction, void *lpvParam)
{
	int i, l;
	THashItem *cur;

	if (hHash)
	{
		l = hHash->iSize;
		for (i = 0; i < l; i++)
		{
			while (hHash->table[i].next)
			{
				cur = hHash->table[i].next;
				hHash->table[i].next = cur->next;
				free(cur->key);
				if (cur->flgCpy && cur->value)
				{
					if (ptrFreeObjectFunction != NULL)
					{
						cur->value = ptrFreeObjectFunction(lpvParam, cur->value);
					}
					else
					{
						free(cur->value);
					}
				}

				free(cur);
			}
		}
	}
}

HHASH hashFree(THash *hHash)
{
	return hashFreeEx(hHash, NULL, NULL);
}

HHASH hashFreeEx(HHASH hHash, TEventFreeObject ptrFreeObjectFunction, void *lpvParam)
{
	if (hHash)
	{
		hashClearEx(hHash, ptrFreeObjectFunction, lpvParam);
		free(hHash->table);
		free(hHash);
	}
	return NULL;
}

void hashSetHashFunction(HHASH hHash, unsigned int (*ptrHashFunction)(char *s, const int iPrime))
{
	if (hHash)
	{
		hHash->hashFunction = ptrHashFunction;
	}
}

char *hashGetNextKey(THash *hHash, char *lpcKey)
{
	int i, l;
	THashItem *cur;
	char caKey[MAX_TAM_KEY];

	if (!hHash)
		return NULL;
	i = -1;
	if (lpcKey)
	{
		strcpy(caKey, lpcKey);

		i = hHash->hashFunction(caKey, hHash->iSize);
		if (hHash->cache && !hashCompare(hHash->cache->key, caKey))
		{
			cur = hHash->cache;
			if (cur->next)
			{
				hHash->cache = cur->next;
				return hHash->cache->key;
			}
		}
		else
		{
			for (cur = hHash->table[i].next; cur; cur = cur->next)
				if (!hashCompare(cur->key, caKey))
				{
					if (cur->next)
					{
						hHash->cache = cur->next;
						return hHash->cache->key;
					}
					break;
				}
		}
	}

	l = hHash->iSize;
	for (i++; i < l; i++)
		if (hHash->table[i].next)
		{
			hHash->cache = hHash->table[i].next;
			return hHash->cache->key;
		}
	return NULL;
}

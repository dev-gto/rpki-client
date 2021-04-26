/*	$Id$ */
/*
 * Copyright (c) 2019 Kristaps Dzonsons <kristaps@bsd.lv>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#include "config.h"

#include <arpa/inet.h>
#include <sys/socket.h>

#include <assert.h>
#include <ctype.h>

#include <dirent.h>
#include <err.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <memory.h>
#include <openssl/asn1.h>
#include <openssl/err.h>
#include <openssl/safestack.h>
#include <openssl/ssl.h>
#include <netdb.h>
#include <sys/stat.h>

#include "extern.h"
#include "hash.h"
#include "test-core.h"

#define TAB 30
#define SEP_LINE_SIZE 110

#define JS_STS_ERROR_INVALID_FILE        100
#define JS_STS_ERROR_INVALID_HOSTNAME    101
#define JS_STS_ERROR_NOT_AFTER           102
#define JS_STS_ERROR_NOT_BEFORE          103
#define JS_STS_ERROR_THIS_UPDATE         104
#define JS_STS_ERROR_NEXT_UPDATE         105
#define JS_STS_ERROR_STALE_DATA          106
#define JS_STS_ERROR_ABOUT_TO_STALE      107
#define JS_STS_ERROR_MISSING_CERTIFICATE 108

#define ORIGIN_UNDEFINED 0
#define ORIGIN_MFT       1
#define ORIGIN_CER       2
#define ORIGIN_CRL       3
#define ORIGIN_ROA       4

#define MSK_TIME_FORMAT "%Y-%m-%dT%H:%M:%SZ"

static unsigned char toAsc (unsigned char c)
{
	unsigned char nib = c & 0x0f;
  	if (nib <= 9)
    	return (nib + '0');
	return (nib - 10 + 'a');
}

static void toHex (unsigned char *lpcAsc, unsigned char *lpcBcd, size_t szBcd)
{
	size_t i;
	for (i = 0; i < szBcd; i++) {
		*lpcAsc++ = toAsc (lpcBcd[i] >> 4);
		*lpcAsc++ = toAsc (lpcBcd[i]);
	}
}

void FileEntry_free(char *entry) {
	if (entry) {
		free(entry);
	}
}

void sessionInit (HSESSION hSession) {
	SSL_library_init();
	SSL_load_error_strings();
	if (hSession) {
		memset (hSession, 0, sizeof (struct Session));
		hSession->lpcLocalRepository = ".";
		hSession->filenames = sk_OPENSSL_STRING_new_null();
		hSession->hCertFilenames = hashNew(0);
		hSession->hCertSerialNumbers = hashNew(0);
		hSession->hASNs = hashNew(0);
		hSession->hV4s = hashNew(0);
		hSession->hV6s = hashNew(0);
		hSession->hStaleMFTs = hashNew(0);
		hSession->hHostnames = hashNew(0);
		hSession->hProcessed = hashNew(0);
	}
}

int sessionFree (HSESSION hSession, int iRtn) {
	if (hSession) {
		hashFree(hSession->hCertFilenames);
		hashFree(hSession->hCertSerialNumbers);
		hashFree(hSession->hASNs);
		hashFree(hSession->hV4s);
		hashFree(hSession->hV6s);
		hashFree(hSession->hStaleMFTs);
		hashFree(hSession->hHostnames);
		hashFree(hSession->hProcessed);
		sk_OPENSSL_STRING_pop_free(hSession->filenames, FileEntry_free);
	}

	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
	ERR_remove_thread_state(NULL);
	ERR_free_strings();

	return iRtn;
}

static void print_sep_line (const char *title)
{
	size_t count;
	size_t i;

	count = SEP_LINE_SIZE;
	if (title && *title) {
		printf ("%s ", title);
		count -= strlen(title) + 1;
	}
	for (i = 0; i < count; i++) {
		printf("=");
	}
	printf("\n");
}

static int hasResources(HSESSION hSession, char *lpcAKI) {
	if (hashGet(hSession->hASNs, lpcAKI) || hashGet(hSession->hV4s, lpcAKI) || hashGet(hSession->hV6s, lpcAKI)) {
		return 1;
	}
	return 0;
}

static void dumpErrors(HSESSION hSession, int iOrigin, Error *errors, char *aki)
{
	Error *lpcError;
	char *lpcASNs;
	char *lpcSep;
	char *lpcIPs;
	char *lpcData;

	if (hSession->iOptOutput == OPT_OUTPUT_JS_MONITOR) {
		if (errors[0].iCode) {
			printf("%s\t\t{\n", hSession->iNumErrorsFound ? ",\n": "\n");
			lpcData = NULL;
			switch (iOrigin) {
				case ORIGIN_CER:
					lpcData = "cer";
					break;
				case ORIGIN_CRL:
					lpcData = "crl";
					break;
				case ORIGIN_MFT:
					lpcData = "mft";
					break;
				case ORIGIN_ROA:
					lpcData = "roa";
					break;
			}
			if (lpcData != NULL) {
				printf("\t\t\t\"type\":\"%s\",\n", lpcData);
			}
			printf("\t\t\t\"filename\":\"%s\",\n", hSession->lpcCurrentFilename);
			lpcSep="";
			if (aki != NULL) {
				if (iOrigin == ORIGIN_MFT) {
					// at stage 1 we have a missing certificate
					if (hSession->iStage != 1) {
						printf("\t\t\t\"parent\": {\n");
						printf("\t\t\t\t\"type\":\"cer\"");
						lpcData = hashGet(hSession->hCertFilenames, aki);
						if (lpcData) {
							printf(",\n\t\t\t\t\"filename\":\"%s\"", lpcData);
						}
						lpcData = hashGet(hSession->hCertSerialNumbers, aki);
						if (lpcData) {
							printf(",\n\t\t\t\t\"serial\":\"%s\"", lpcData);
						}
						printf("\n\t\t\t},\n");
					}
				} else if (iOrigin == ORIGIN_CRL || iOrigin == ORIGIN_ROA) {
					printf("\t\t\t\"parent\": {\n");
					printf("\t\t\t\t\"type\":\"mft\"");
					lpcData = hashGet(hSession->hStaleMFTs, aki);
					if (lpcData) {
						printf(",\n\t\t\t\t\"filename\":\"%s\"", lpcData);
					}
					printf("\n\t\t\t},\n");
				}

				if (hasResources(hSession, aki)) {
					printf("\t\t\t\"resources\": {\n");
					lpcASNs = hashGet(hSession->hASNs, aki);
					if (lpcASNs) {
						printf("%s\t\t\t\t\"asn\":\"%s\"", lpcSep, lpcASNs);
						lpcSep=",\n";
					}
					lpcIPs = hashGet(hSession->hV4s, aki);
					if (lpcIPs != NULL) {
						printf("%s\t\t\t\t\"v4\":\"%s\"", lpcSep, lpcIPs);
						lpcSep=",\n";
					}
					lpcIPs = hashGet(hSession->hV6s, aki);
					if (lpcIPs != NULL) {
						printf("%s\t\t\t\t\"v6\":\"%s\"", lpcSep, lpcIPs);
						lpcSep=",\n";
					}
					printf("\n\t\t\t},\n");
				}
			}
			printf("\t\t\t\"errors\":[");
			lpcSep="";
			for (lpcError = errors; lpcError->iCode; lpcError++) {
				printf("%s\n\t\t\t\t{\"code\":%d, \"description\":\"%s\""
				, lpcSep
				, lpcError->iCode
				, lpcError->lpcDescription
				);
				if (lpcError->lpcReceived) {
					printf(", \"recv\":\"%s\"", lpcError->lpcReceived);
				}
				if (lpcError->lpcReference) {
					printf(", \"ref\":\"%s\"", lpcError->lpcReference);
				}
				printf("}");
				lpcSep = ",";
				hSession->iNumErrorsFound++;
			}
			printf("\n\t\t\t]\n");
			printf("\t\t}");
		}
	}

	if (hSession->iOptOutput == OPT_OUTPUT_TEXT && hSession->iStage == 1) {
		printf("[Warning] Missing certificate\n");
	}
}

static int hostnameStatus(char *lpcHostname) 
{
	int iResult;
	struct addrinfo hints = {}, *addrs = NULL;

	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	iResult = getaddrinfo(lpcHostname , NULL, &hints, &addrs);
	if (iResult == 0) {
		freeaddrinfo(addrs);
	}
	return iResult;
}

void print_cert(HSESSION hSession, const struct cert *p)
{
	int iNumErrors;
	int	 sockt;
	int iFlgFreeFilename;
	int iValidHostname;
	char *lpcBasename;
	char *lpcFilename;
	char *lpcHostname;
	char *lpcLocation;
	char *lpcSep;
	size_t	 i;
	char	 buf1[64], buf2[64];
	char caNotAfter[64], caNotBefore[64], caNow[64];
	time_t now;
	struct tm *tm;
	struct stat st;
	Error errors[8];

	assert(p != NULL);
	iNumErrors = 0;
	memset(errors, 0, sizeof(errors));

    now = time(NULL);
	tm = gmtime(&now);
	strftime(caNow, sizeof(caNow)-1, MSK_TIME_FORMAT, tm);

	tm = gmtime(&p->basic.notBefore);
	strftime(caNotBefore, sizeof(caNotBefore)-1, MSK_TIME_FORMAT, tm);

	tm = gmtime(&p->basic.notAfter);
	strftime(caNotAfter, sizeof(caNotAfter)-1, MSK_TIME_FORMAT, tm);

	if (strcmp(caNow, caNotBefore) < 0) {
		errors[iNumErrors].iCode = JS_STS_ERROR_NOT_BEFORE;
		errors[iNumErrors].lpcDescription = "notBefore not yet valid";
		errors[iNumErrors].lpcReceived = caNotBefore;
		errors[iNumErrors].lpcReference = caNow;
		iNumErrors++;
	}
	if (strcmp(caNow, caNotAfter) > 0) {
		errors[iNumErrors].iCode = JS_STS_ERROR_NOT_AFTER;
		errors[iNumErrors].lpcDescription = "notAfter expired";
		errors[iNumErrors].lpcReceived = caNotAfter;
		errors[iNumErrors].lpcReference = caNow;
		iNumErrors++;
	}

	if (hSession->iOptRecursive) {
		hashRemoveKey(hSession->hASNs, p->basic.ski);
		hashRemoveKey(hSession->hV4s, p->basic.ski);
		hashRemoveKey(hSession->hV6s, p->basic.ski);

		hashSetCpy(hSession->hCertFilenames, p->basic.ski, hSession->lpcCurrentFilename);
		hashSetCpy(hSession->hCertSerialNumbers, p->basic.ski, p->basic.serial);
		for (i = 0; i < p->asz; i++) {
			switch (p->as[i].type) {
			case CERT_AS_ID:
				sprintf(buf1, "%"PRIu32, p->as[i].id);
				hashSetCat(hSession->hASNs, p->basic.ski, buf1, ',');
				break;

			case CERT_AS_RANGE:
				sprintf(buf1, "%"PRIu32 "-%" PRIu32, p->as[i].range.min, p->as[i].range.max);
				hashSetCat(hSession->hASNs, p->basic.ski, buf1, ',');
				break;

			default:
				break;
			}
		}

		for (i = 0; i < p->ipsz; i++)
			switch (p->ips[i].type) {
			case CERT_IP_ADDR:
				ip_addr_print(&p->ips[i].ip,
					p->ips[i].afi, buf1, sizeof(buf1));
				if (p->ips[i].afi == AFI_IPV4) {
					hashSetCat(hSession->hV4s, p->basic.ski, buf1, ',');
				} else {
					hashSetCat(hSession->hV6s, p->basic.ski, buf1, ',');
				}
				break;

			case CERT_IP_RANGE:
				sockt = (p->ips[i].afi == AFI_IPV4) ?
					AF_INET : AF_INET6;
				inet_ntop(sockt, p->ips[i].min, buf1, sizeof(buf1));
				inet_ntop(sockt, p->ips[i].max, buf2, sizeof(buf2));
				char caBuf[256];
				sprintf(caBuf, "%s-%s", buf1, buf2);

				if (p->ips[i].afi == AFI_IPV4) {
					hashSetCat(hSession->hV4s, p->basic.ski, caBuf, ',');
				} else {
					hashSetCat(hSession->hV6s, p->basic.ski, caBuf, ',');
				}
				break;

			default:
				break;
			}


		lpcLocation = strdup(p->mft);
		lpcBasename = lpcLocation;
		// strip protocol from lpcBasename
		if (memcmp(lpcBasename, "rsync://", 8) == 0 || memcmp(lpcBasename, "https://", 8) == 0) {
			lpcBasename += 8;
		}
		// Check hostname
		lpcHostname = NULL;
		lpcSep = strchr(lpcBasename, '/');
		if (lpcSep != NULL) {
			*lpcSep = 0;
			iValidHostname = hashGetAsInt(hSession->hHostnames, lpcBasename);
			if (iValidHostname == 0) { // Not in cache
				if (strcasecmp(lpcBasename, "localhost") == 0 || strcmp(lpcBasename, "127.0.0.1") == 0 || hostnameStatus(lpcBasename) != 0) {
					iValidHostname = 2;
				} 
				else {
					iValidHostname = 1;
				}
				hashSetInt(hSession->hHostnames, lpcBasename, iValidHostname);
			}
			if (iValidHostname == 2) {
				lpcHostname = strdup(lpcBasename);
				errors[iNumErrors].iCode = JS_STS_ERROR_INVALID_HOSTNAME;
				errors[iNumErrors].lpcDescription = "invalid hostname";
				errors[iNumErrors].lpcReceived = lpcHostname;
				errors[iNumErrors].lpcReference = hSession->lpcCurrentFilename;

				iNumErrors++;
			}
			*lpcSep = '/';
		}
		iFlgFreeFilename = 1;
		lpcFilename = malloc(strlen(hSession->lpcLocalRepository) + 1 + strlen(lpcBasename) + 1);
		if (lpcFilename != NULL) {
			strcpy (lpcFilename, hSession->lpcLocalRepository);
			strcat (lpcFilename, "/");
			strcat (lpcFilename, lpcBasename);
			if (stat (lpcFilename, &st) == 0 && (S_ISREG(st.st_mode) || S_ISLNK(st.st_mode))) {
				// Just append
				sk_OPENSSL_STRING_push(hSession->filenames, lpcFilename);
				iFlgFreeFilename = 0;
			} 
			else {
				errors[iNumErrors].iCode = JS_STS_ERROR_INVALID_FILE;
				errors[iNumErrors].lpcDescription = "invalid file";
				errors[iNumErrors].lpcReference = lpcFilename;
			}
		}

		dumpErrors(hSession, ORIGIN_CER, errors, p->basic.ski);

		if (iFlgFreeFilename) {
			free(lpcFilename);
		}
		free(lpcHostname);
		free(lpcLocation);
	}

	if (hSession->iOptOutput == OPT_OUTPUT_TEXT) {
		printf("%*.*s: %s\n", TAB, TAB, "Now", caNow);
		print_sep_line("Certificate");
		printf("%*.*s: %ld\n", TAB, TAB, "Version", p->basic.version);
		printf("%*.*s: %s\n", TAB, TAB, "Serial", p->basic.serial);
		printf("%*.*s: %s\n", TAB, TAB, "Issuer", p->basic.issuerName);
		printf("%*.*s: %s\n", TAB, TAB, "Subject", p->basic.subject);
		printf("%*.*s: %s\n", TAB, TAB, "Not Before", caNotBefore);
		printf("%*.*s: %s\n", TAB, TAB, "Not After", caNotAfter);
		printf("%*.*s: %s\n", TAB, TAB, "Subject key identifier", p->basic.ski);
		if (p->basic.aki != NULL) {
			printf("%*.*s: %s\n", TAB, TAB, "Authority key identifier", p->basic.aki);
		}

		printf("%*.*s: %s\n", TAB, TAB, "Manifest", p->mft);
		if (p->rep != NULL) {
			printf("%*.*s: %s\n", TAB, TAB, "Repository", p->rep);
		}
		if (p->crl != NULL) {
			printf("%*.*s: %s\n", TAB, TAB, "Revocation list", p->crl);
		}
		for (i = 0; i < p->asz; i++)
			switch (p->as[i].type) {
			case CERT_AS_ID:
				printf("%*zu: AS: %"
					PRIu32"\n", TAB, i + 1, p->as[i].id);
				break;
			case CERT_AS_INHERIT:
				printf("%*zu: AS: inherit\n", TAB, i + 1);
				break;
			case CERT_AS_RANGE:
				printf("%*zu: AS: %"
					PRIu32 "-%" PRIu32 "\n", TAB, i + 1,
					p->as[i].range.min, p->as[i].range.max);
				break;
			}
		for (i = 0; i < p->ipsz; i++)
			switch (p->ips[i].type) {
			case CERT_IP_INHERIT:
				printf("%*zu: IP: inherit\n", TAB, i + 1);
				break;
			case CERT_IP_ADDR:
				ip_addr_print(&p->ips[i].ip,
					p->ips[i].afi, buf1, sizeof(buf1));
				printf("%*zu: IP: %s\n",TAB,  i + 1, buf1);
				break;
			case CERT_IP_RANGE:
				sockt = (p->ips[i].afi == AFI_IPV4) ?
					AF_INET : AF_INET6;
				inet_ntop(sockt, p->ips[i].min, buf1, sizeof(buf1));
				inet_ntop(sockt, p->ips[i].max, buf2, sizeof(buf2));
				printf("%*zu: IP: %s-%s\n", TAB, i + 1, buf1, buf2);
				break;
			}
		printf("\n");
	}
}

// http://www.geo-complex.com/shares/soft/unix/CentOS/OpenVPN/openssl-1.1.0c/crypto/x509/x_crl.c
void print_crl (HSESSION hSession, X509_CRL *p)
{
	int i, numRevoked;
	int iNumErrors;
	char caRevocationDate[64];
	char caLast[64], caNext[64], caNow[64];
	char *issuerName, *aki;
	time_t now;
	struct tm tm;
	ASN1_INTEGER *n;
	STACK_OF(X509_REVOKED) *revoked;
	Error errors[4];

	assert(p != NULL);
	iNumErrors = 0;
	memset (errors, 0, sizeof(errors));

    now = time(NULL);
	strftime(caNow, sizeof(caNow)-1, MSK_TIME_FORMAT, gmtime(&now));

	revoked = X509_CRL_get_REVOKED(p);

	tm = asn1Time2Time(X509_CRL_get0_lastUpdate(p));
	strftime(caLast, sizeof(caLast)-1, MSK_TIME_FORMAT, &tm);

	tm = asn1Time2Time(X509_CRL_get0_nextUpdate(p));
	strftime(caNext, sizeof(caNext)-1, MSK_TIME_FORMAT, &tm);

	if (strcmp(caNow, caLast) < 0) {
		errors[iNumErrors].iCode = JS_STS_ERROR_THIS_UPDATE;
		errors[iNumErrors].lpcDescription = "thisUpdate not yet valid";
		errors[iNumErrors].lpcReceived = caLast;
		errors[iNumErrors].lpcReference = caNow;
		iNumErrors++;
	}
	if (strcmp(caNow, caNext) > 0) {
		errors[iNumErrors].iCode = JS_STS_ERROR_NEXT_UPDATE;
		errors[iNumErrors].lpcDescription = "nextUpdate expired";
		errors[iNumErrors].lpcReceived = caNext;
		errors[iNumErrors].lpcReference = caNow;
		iNumErrors++;
	}

	aki = x509_crl_get_aki(p);
	issuerName = X509_NAME_oneline(X509_CRL_get_issuer(p), NULL, 0);

	if (hSession->iStage == 1) {
		errors[iNumErrors].iCode = JS_STS_ERROR_MISSING_CERTIFICATE;
		errors[iNumErrors].lpcDescription = "missing certificate";
		if (issuerName != NULL) {
			errors[iNumErrors].lpcReceived = issuerName;
		} else {
			errors[iNumErrors].lpcReceived = aki;
		}
		iNumErrors++;
	}

	dumpErrors(hSession, ORIGIN_CRL, errors, aki);
	free(aki);

	if (hSession->iOptOutput == OPT_OUTPUT_TEXT) {
		printf("%*.*s: %s\n", TAB, TAB, "Now", caNow);
		print_sep_line("Certificate Revocation List");
		printf("%*.*s: %ld\n", TAB, TAB, "Version", X509_CRL_get_version(p) + 1);

		n = X509_CRL_get_ext_d2i(p,NID_crl_number,NULL,NULL);
		if (n != NULL) {
			printf("%*.*s: %ld\n", TAB, TAB, "CRL Number", ASN1_INTEGER_get(n));
			ASN1_INTEGER_free(n);
		}

		if (issuerName != NULL) {
			printf("%*.*s: %s\n", TAB, TAB, "Issuer", issuerName);
		}

		printf("%*.*s: %s\n", TAB, TAB, "Last Update", caLast);
		printf("%*.*s: %s\n", TAB, TAB, "Next Update", caNext);

		numRevoked = sk_X509_REVOKED_num(revoked);
		if (numRevoked > 0) {
			print_sep_line("Revoked Certificates");
			for (i = 0; i < numRevoked; i++) {
				X509_REVOKED *rev = sk_X509_REVOKED_value(revoked, i);
				if (rev != NULL) {
					BIGNUM *bnSrl = ASN1_INTEGER_to_BN(X509_REVOKED_get0_serialNumber(rev), NULL);
					if (bnSrl != NULL) {
						char *lpcSrl = BN_bn2hex(bnSrl);
						if (lpcSrl != NULL) {
							printf("%*.*s: %s\n", TAB, TAB, "Serial Number", lpcSrl);
							OPENSSL_free(lpcSrl);
						}
						BN_free(bnSrl);
					}
				}
				tm = asn1Time2Time(X509_REVOKED_get0_revocationDate(rev));
				strftime(caRevocationDate, sizeof(caRevocationDate)-1, MSK_TIME_FORMAT, &tm);
				printf("%*.*s:    %s\n", TAB, TAB, "Revokation Date", caRevocationDate);
			}
		}
		printf("\n");
	}
	if (issuerName != NULL) {
		OPENSSL_free(issuerName);
	}
}

void print_mft(HSESSION hSession, const struct mft *p)
{
	int iCurrentSlot;
	int iNumErrors;
	char *lpcBasename;
	char *lpcFilename;
	char *lpcLocation;
	size_t	 i;
	unsigned char caSHA256[64 + 1];
	char caNotAfter[64], caNotBefore[64], caThis[64], caNext[64], caNow[64], caStale[64];
	time_t now;
	time_t stale;
	struct tm *tm;
	struct stat st;
	Error errors[5];

	assert(p != NULL);
	iNumErrors = 0;
	memset (errors, 0, sizeof(errors));

    now = time(NULL);
	tm = gmtime(&now);
	strftime(caNow, sizeof(caNow)-1, MSK_TIME_FORMAT, tm);

	tm = gmtime(&p->thisUpdate);
	strftime(caThis, sizeof(caThis)-1, MSK_TIME_FORMAT, tm);

	tm = gmtime(&p->nextUpdate);
	strftime(caNext, sizeof(caNext)-1, MSK_TIME_FORMAT, tm);

	tm = gmtime(&p->eeCert.notBefore);
	strftime(caNotBefore, sizeof(caNotBefore)-1, MSK_TIME_FORMAT, tm);

	tm = gmtime(&p->eeCert.notAfter);
	strftime(caNotAfter, sizeof(caNotAfter)-1, MSK_TIME_FORMAT, tm);

	if (strcmp(caNow, caThis) < 0) {
		errors[iNumErrors].iCode = JS_STS_ERROR_THIS_UPDATE;
		errors[iNumErrors].lpcDescription = "thisUpdate not yet valid";
		errors[iNumErrors].lpcReceived = caThis;
		errors[iNumErrors].lpcReference = caNow;
		iNumErrors++;
	}
	if (strcmp(caNow, caNext) > 0) {
		errors[iNumErrors].iCode = JS_STS_ERROR_NEXT_UPDATE;
		errors[iNumErrors].lpcDescription = "nextUpdate expired";
		errors[iNumErrors].lpcReceived = caNext;
		errors[iNumErrors].lpcReference = caNow;
		iNumErrors++;
	}
	else if (hSession->iOptAboutToStaleSeconds > 0) {
		stale = p->nextUpdate - hSession->iOptAboutToStaleSeconds;
		tm = gmtime(&stale);
		strftime(caStale, sizeof(caStale)-1, MSK_TIME_FORMAT, tm);
		if (strcmp(caNow, caStale) > 0) {
			errors[iNumErrors].iCode = JS_STS_ERROR_ABOUT_TO_STALE;
			errors[iNumErrors].lpcDescription = "nextUpdate about to stale";
			errors[iNumErrors].lpcReceived = caNext;
			errors[iNumErrors].lpcReference = caStale;
			iNumErrors++;
		}
	}
	if (strcmp(caNow, caNotBefore) < 0) {
		errors[iNumErrors].iCode = JS_STS_ERROR_NOT_BEFORE;
		errors[iNumErrors].lpcDescription = "notBefore not yet valid";
		errors[iNumErrors].lpcReceived = caNotBefore;
		errors[iNumErrors].lpcReference = caNow;
		iNumErrors++;
	}
	if (strcmp(caNow, caNotAfter) > 0) {
		errors[iNumErrors].iCode = JS_STS_ERROR_NOT_AFTER;
		errors[iNumErrors].lpcDescription = "notAfter expired";
		errors[iNumErrors].lpcReceived = caNotAfter;
		errors[iNumErrors].lpcReference = caNow;
		iNumErrors++;
	}
	if (hSession->iStage == 1 && p->filesz > 0) {
		errors[iNumErrors].iCode = JS_STS_ERROR_MISSING_CERTIFICATE;
		errors[iNumErrors].lpcDescription = "missing certificate";
		errors[iNumErrors].lpcReceived = p->eeCert.issuerName;
		iNumErrors++;
	}

	dumpErrors(hSession, ORIGIN_MFT, errors, p->eeCert.aki);

	if (iNumErrors) {
		// From now on future calls to dumpErrors will analyze aki
		hashSetCpy(hSession->hStaleMFTs, p->eeCert.aki, hSession->lpcCurrentFilename);
	}

	lpcLocation = strdup(p->eeCert.eeLocation);
	lpcBasename = lpcLocation;
	// strip protocol from lpcBasename
	if (memcmp(lpcBasename, "rsync://", 8) == 0 || memcmp(lpcBasename, "https://", 8) == 0) {
		lpcBasename += 8;
	}

	// strip filename from lpcBasename
	for (i = strlen(lpcBasename) - 1; i; i--) {
		if (lpcBasename[i - 1] == '/') {
			lpcBasename[i] = 0;
			break;
		}
	}

	if (hSession->iOptOutput == OPT_OUTPUT_TEXT) {
		printf("%*.*s: %s\n", TAB, TAB, "Now", caNow);
		print_sep_line("EE Certificate");
		printf("%*.*s: %ld\n", TAB, TAB, "Version", p->eeCert.version);
		printf("%*.*s: %s\n", TAB, TAB, "Serial", p->eeCert.serial);
		printf("%*.*s: %s\n", TAB, TAB, "Issuer", p->eeCert.issuerName);
		printf("%*.*s: %s\n", TAB, TAB, "Subject", p->eeCert.subject);
		printf("%*.*s: %s\n", TAB, TAB, "Not Before", caNotBefore);
		printf("%*.*s: %s\n", TAB, TAB, "Not After", caNotAfter);
		printf("%*.*s: %s\n", TAB, TAB, "Subject Info Access", p->eeCert.eeLocation);
		printf("%*.*s: %s\n", TAB, TAB, "Subject key identifier", p->eeCert.ski);
		printf("%*.*s: %s\n", TAB, TAB, "Authority key identifier", p->eeCert.aki);
		print_sep_line("Manifest");

		printf("%*.*s: %ld\n", TAB, TAB, "Manifest Number", p->manifestNumber);
		printf("%*.*s: %s\n", TAB, TAB, "This Update", caThis);
		printf("%*.*s: %s\n", TAB, TAB, "Next Update", caNext);
	}

	iCurrentSlot = 0;
	for (i = 0; i < p->filesz; i++) {
		memset (caSHA256, 0, sizeof (caSHA256));
		toHex(caSHA256, p->files[i].hash, 32);
		if (hSession->iOptOutput == OPT_OUTPUT_TEXT) {
			printf("%s  %s\n", caSHA256, p->files[i].file);
		}
		if (hSession->iStage != 1 && hSession->iOptRecursive) {
			// Append filename for processing
			lpcFilename = malloc(strlen(hSession->lpcLocalRepository) + 1 + strlen(lpcBasename) + strlen(p->files[i].file) + 1);
			if (lpcFilename != NULL) {
				strcpy (lpcFilename, hSession->lpcLocalRepository);
				strcat (lpcFilename, "/");
				strcat (lpcFilename, lpcBasename);
				strcat (lpcFilename, p->files[i].file);
				if (stat (lpcFilename, &st) == 0 && (S_ISREG(st.st_mode) || S_ISLNK(st.st_mode))) {
					if (strcasecmp(lpcFilename + strlen(lpcFilename) - 4, ".crl") == 0) {
						// Prioritize crl
						sk_OPENSSL_STRING_insert(hSession->filenames, lpcFilename, 0);
						iCurrentSlot++;
					}
					else {
						sk_OPENSSL_STRING_insert(hSession->filenames, lpcFilename, iCurrentSlot++);
					}
				} 
				else {
					fprintf(stderr, "Invalid entry [%s]\n", lpcFilename);
					free (lpcFilename);
				}
			}
		}
	}
	if (hSession->iOptOutput == OPT_OUTPUT_TEXT) {
		printf("\n");
	}
	free(lpcLocation);
}

// ROA
void print_roa(HSESSION hSession, const struct roa *p)
{
	int iNumErrors;
	char	 buf[256];
	size_t	 i;
	char caNotAfter[64], caNotBefore[64], caNow[64];
	time_t now;
	struct tm *tm;
	Error *errors;

	assert(p != NULL);
	iNumErrors = 0;
	errors = malloc(sizeof(Error)*(4+p->ipsz));
	if (errors == NULL) {
		return;
	}
	memset (errors, 0, sizeof(Error)*(4+p->ipsz));

    now = time(NULL);
	tm = gmtime(&now);
	strftime(caNow, sizeof(caNow)-1, MSK_TIME_FORMAT, tm);

	tm = gmtime(&p->eeCert.notBefore);
	strftime(caNotBefore, sizeof(caNotBefore)-1, MSK_TIME_FORMAT, tm);

	tm = gmtime(&p->eeCert.notAfter);
	strftime(caNotAfter, sizeof(caNotAfter)-1, MSK_TIME_FORMAT, tm);

	if (strcmp(caNow, caNotBefore) < 0) {
		errors[iNumErrors].iCode = JS_STS_ERROR_NOT_BEFORE;
		errors[iNumErrors].lpcDescription = "notBefore not yet valid";
		errors[iNumErrors].lpcReceived = caNotBefore;
		errors[iNumErrors].lpcReference = caNow;
		iNumErrors++;
	}
	if (strcmp(caNow, caNotAfter) > 0) {
		errors[iNumErrors].iCode = JS_STS_ERROR_NOT_AFTER;
		errors[iNumErrors].lpcDescription = "notAfter expired";
		errors[iNumErrors].lpcReceived = caNotAfter;
		errors[iNumErrors].lpcReference = caNow;
		iNumErrors++;
	}

	if (hashGet(hSession->hStaleMFTs, p->eeCert.aki)) {
		errors[iNumErrors].iCode = JS_STS_ERROR_STALE_DATA;
		errors[iNumErrors].lpcDescription = "stale data";
		char caLine[1024];
		char caMax[32];
		memset (caLine, 0, sizeof (caLine));
		sprintf(caLine, "asn=%"PRIu32"; ip=", p->asid);
		char *lpcSep="";
		for (i = 0; i < p->ipsz; i++) {
			ip_addr_print(&p->ips[i].addr,
				p->ips[i].afi, buf, sizeof(buf));
			sprintf(caMax, "/%zu", p->ips[i].maxlength);
			if (strlen(buf) > strlen(caMax) && strcmp(buf + strlen(buf) - strlen(caMax), caMax) != 0) {
				strcat (buf, "-");
				strcat (buf, caMax + 1);
			}
			strncat (caLine, lpcSep, sizeof(caLine) - 2);
			strncat (caLine, buf, sizeof(caLine) - 2);
			lpcSep = ",";
		}
		strcat (caLine, ";");

		errors[iNumErrors].lpcReceived = caLine;
		iNumErrors++;
	}
	if (hSession->iStage == 1) {
		errors[iNumErrors].iCode = JS_STS_ERROR_MISSING_CERTIFICATE;
		errors[iNumErrors].lpcDescription = "missing certificate";
		errors[iNumErrors].lpcReceived = p->eeCert.issuerName;
		iNumErrors++;
	}

	dumpErrors(hSession, ORIGIN_ROA, errors, p->eeCert.aki);
	free(errors);

	if (hSession->iOptOutput == OPT_OUTPUT_TEXT) {
		printf("%*.*s: %s\n", TAB, TAB, "Now", caNow);
		print_sep_line("EE Certificate");
		printf("%*.*s: %ld\n", TAB, TAB, "Version", p->eeCert.version);
		printf("%*.*s: %s\n", TAB, TAB, "Serial", p->eeCert.serial);
		printf("%*.*s: %s\n", TAB, TAB, "Issuer", p->eeCert.issuerName);
		printf("%*.*s: %s\n", TAB, TAB, "Subject", p->eeCert.subject);
		printf("%*.*s: %s\n", TAB, TAB, "Not Before", caNotBefore);
		printf("%*.*s: %s\n", TAB, TAB, "Not After", caNotAfter);
		printf("%*.*s: %s\n", TAB, TAB, "Subject Info Access", p->eeCert.eeLocation);
		printf("%*.*s: %s\n", TAB, TAB, "Subject key identifier", p->eeCert.ski);
		printf("%*.*s: %s\n", TAB, TAB, "Authority key identifier", p->eeCert.aki);
		print_sep_line("ROA");
		printf("%*.*s: %" PRIu32 "\n", TAB, TAB, "asID", p->asid);
		for (i = 0; i < p->ipsz; i++) {
			ip_addr_print(&p->ips[i].addr,
				p->ips[i].afi, buf, sizeof(buf));
			printf("%*zu: %s (max: %zu)\n", TAB, i + 1,
				buf, p->ips[i].maxlength);
		}
		printf("\n");
	}
}

// TAL
void print_tal(HSESSION hSession, const struct tal *p)
{
	size_t	 i;
	unsigned char *lpcBuffer;

	assert(p != NULL);

	if (hSession->iOptOutput == OPT_OUTPUT_TEXT) {
		lpcBuffer = malloc(p->pkeysz * 2 + 1);
		if (lpcBuffer != NULL) {
			memset(lpcBuffer, 0, p->pkeysz * 2 + 1);
			toHex(lpcBuffer, p->pkey, p->pkeysz);
			printf("%*.*s: %s\n", TAB, TAB, "Public Key", lpcBuffer);
			free(lpcBuffer);
		}
		print_sep_line("URI");
		for (i = 0; i < p->urisz; i++)
			printf("%*zu: %s\n", TAB, i + 1, p->uri[i]);
		printf("\n");
	}
}

// This is not an original code from openbsd
struct tal *
tal_parse_from_file(const char *fn)
{
	char		*buf;
	struct tal	*p;

	p = NULL;
    buf = tal_read_file(fn);
	if (buf != NULL) {
		p = tal_parse(fn, buf);
		free (buf);
	}

	return p;
}

static void processFile(HSESSION hSession, char *lpcFilename) {
	int optSilent;
	size_t		 sz;
	struct cert	*cert;
	struct mft	*mft;
	struct roa	*roa;
	struct tal	*tal;
	X509_CRL	*crl;
	X509		*xp = NULL;

	if (hashGetAsInt(hSession->hProcessed, lpcFilename)) {
		// skip already processed
		return;
	}

	sz = strlen(lpcFilename);
	hSession->lpcCurrentFilename = lpcFilename;
	if (strcasecmp(lpcFilename + sz - 4, ".mft") == 0) {
		if ((mft = mft_parse(&xp, lpcFilename, 1)) != NULL) {
			print_mft(hSession, mft);
			mft_free(mft);
		}
	}
	else if (strcasecmp(lpcFilename + sz - 4, ".roa") == 0) {
		if ((roa = roa_parse(&xp, lpcFilename)) != NULL) {
			print_roa(hSession, roa);
			roa_free(roa);
		}
	}
	else if (strcasecmp(lpcFilename + sz - 4, ".crl") == 0) {
		if ((crl = crl_parse(lpcFilename)) != NULL) {
			print_crl(hSession, crl);
			X509_CRL_free(crl);
		}
	}
	else if (strcasecmp(lpcFilename + sz - 4, ".tal") == 0) {
		if ((tal = tal_parse_from_file(lpcFilename)) != NULL) {
			print_tal(hSession, tal);
			tal_free(tal);
		}
	}
	else {
		optSilent = log_get_silent();
		log_set_silent(1);
		// Try checking a TA cert
		cert = ta_parse(&xp, lpcFilename, NULL, 0);
		log_set_silent(optSilent);
		if (cert != NULL) {
			print_cert(hSession, cert);
			cert_free(cert);
		} else {
			log_set_silent(1);
			cert = cert_parse(&xp, lpcFilename, NULL);
			log_set_silent(optSilent);
			if (cert != NULL) {
				print_cert(hSession, cert);
				cert_free(cert);
			}
			else {
				log_set_silent(optSilent);
				// Try checking a TAL
				tal = tal_parse_from_file(lpcFilename);
				log_set_silent(optSilent);
				if (tal != NULL) {
					print_tal(hSession, tal);
					tal_free(tal);
				}
				else {
					log_warnx("Unrecognized file [%s]", lpcFilename);
				}
			}
		}
	}

	if (xp != NULL) {
		X509_free(xp);
		xp = NULL;
	}
	hashSetInt(hSession->hProcessed, lpcFilename, 1);
}

static void getMissingFiles(HSESSION hSession, char *lpcDirectory) {
	int iFlgFreeFilename;
	size_t sz;
    DIR *dir;
	char *lpcFilename;
    struct dirent *entry;
	struct stat st;

    if (!(dir = opendir(lpcDirectory)))
        return;

    while ((entry = readdir(dir)) != NULL) {
		iFlgFreeFilename = 1;
		lpcFilename = malloc(strlen(lpcDirectory) + 1 + strlen(entry->d_name) + 1);
		strcpy (lpcFilename, lpcDirectory);
		strcat (lpcFilename, "/");
		strcat (lpcFilename, entry->d_name);
        if (entry->d_type == DT_DIR) {
            if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
	            getMissingFiles(hSession, lpcFilename);
			}
        } else if (!hashGetAsInt(hSession->hProcessed, lpcFilename)) {
			// For now only consider .mft files
			sz = strlen(lpcFilename);
			if (strcasecmp(lpcFilename + sz - 4, ".mft") == 0) {
				if (stat (lpcFilename, &st) == 0 && (S_ISREG(st.st_mode) || S_ISLNK(st.st_mode))) {
					sk_OPENSSL_STRING_push(hSession->filenames, lpcFilename);
					iFlgFreeFilename = 0;
				}
			}
        }
		if (iFlgFreeFilename) {
			free(lpcFilename);
		}
    }
    closedir(dir);
}

static void processMissingFiles(HSESSION hSession) {
	if (hSession->lpcCheckCertDirectory != NULL) {
		hSession->iStage = 1;
		getMissingFiles(hSession, hSession->lpcCheckCertDirectory);
		while (sk_OPENSSL_STRING_num(hSession->filenames) > 0) {
			char *lpcFilename = sk_OPENSSL_STRING_value(hSession->filenames, 0);
			sk_OPENSSL_STRING_delete(hSession->filenames, 0);
			if (hSession->iOptOutput == OPT_OUTPUT_TEXT) {
				printf("Processing [%s]:\n", lpcFilename);
			}
			processFile(hSession, lpcFilename);
			FileEntry_free(lpcFilename);
		}
	}
}

void jsMonitor(HSESSION hSession) {
	char caNow[64];
	time_t now;
	struct tm *tm;

    now = time(NULL);
	tm = gmtime(&now);
	strftime(caNow, sizeof(caNow)-1, MSK_TIME_FORMAT, tm);

	printf("{\n\t\"reference date\":\"%s\",\n\t\"objects\":[", caNow);
	while (sk_OPENSSL_STRING_num(hSession->filenames) > 0) {
		char *lpcFilename = sk_OPENSSL_STRING_value(hSession->filenames, 0);
		sk_OPENSSL_STRING_delete(hSession->filenames, 0);
		processFile(hSession, lpcFilename);
		FileEntry_free(lpcFilename);
	}

	processMissingFiles(hSession);

	if (hSession->iNumErrorsFound) {
		printf("\n\t");
	}
	printf("]\n}\n");
}

void txtDump(HSESSION hSession) {
	while (sk_OPENSSL_STRING_num(hSession->filenames) > 0) {
		char *lpcFilename = sk_OPENSSL_STRING_value(hSession->filenames, 0);
		sk_OPENSSL_STRING_delete(hSession->filenames, 0);
		printf("Processing [%s]:\n", lpcFilename);
		processFile(hSession, lpcFilename);
		FileEntry_free(lpcFilename);
	}

	processMissingFiles(hSession);
}

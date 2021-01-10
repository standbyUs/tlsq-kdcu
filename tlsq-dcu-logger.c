#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <pthread.h>
#include <sys/time.h>
#include <time.h>
#include "_tlsq-dcu-logger.h"

char gTlsqDcuVersion[100] = "none";
static pthread_mutex_t gTlsqDcuDebugMutex;
static TLSQ_DCU_DEBUG_LEVEL gTlsqDcuDebugLevel = TLSQ_DCU_DEBUG_NONE;

void SetTlsqDcuDebugLevel(TLSQ_DCU_DEBUG_LEVEL eLevel) {
	pthread_mutex_init(&gTlsqDcuDebugMutex, NULL);
	gTlsqDcuDebugLevel = eLevel;
	return;
}

void PrintTlsqDcuDebug(TLSQ_DCU_DEBUG_LEVEL eLevel, const char *format, ...) {
	if(gTlsqDcuDebugLevel == TLSQ_DCU_DEBUG_NONE)
		return;

	if (eLevel > gTlsqDcuDebugLevel && TLSQ_DCU_DEBUG_DEBUG != (eLevel -1))
		return;

	pthread_mutex_lock(&gTlsqDcuDebugMutex);
	va_list ap;
	va_start(ap, format);
	
	if (eLevel==TLSQ_DCU_DEBUG_ERROR) { printf("\e[31m[TLSQ_DCU_ERROR]\e[m %d ", (int)pthread_self()); }
	else if (eLevel==TLSQ_DCU_DEBUG_DEBUG) { printf("\e[32m[TLSQ_DCU_DEBUG]\e[m %d ", (int)pthread_self()); }
	else if (eLevel==TLSQ_DCU_DEBUG_INFO) { printf("\e[32m[TLSQ_DCU_INFO ]\e[m %d ", (int)pthread_self()); }
	else { va_end(ap); pthread_mutex_unlock(&gTlsqDcuDebugMutex); return;}

	struct timeval tv; gettimeofday(&tv, NULL); struct tm tmTime; localtime_r(&tv.tv_sec, &tmTime);
	printf("%02d:%02d:%02d.%06d version:%s ", tmTime.tm_hour, tmTime.tm_min, tmTime.tm_sec, (int)tv.tv_usec, gTlsqDcuVersion);
	vprintf(format,ap);

	va_end(ap);
	pthread_mutex_unlock(&gTlsqDcuDebugMutex);
}


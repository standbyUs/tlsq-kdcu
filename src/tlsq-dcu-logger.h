#ifndef __TSLQ_DCU_LOGGER_H__
#define __TSLQ_DCU_LOGGER_H__

#include "_tlsq-dcu-logger.h"

#ifdef __cplusplus
extern "C" {
#endif

extern char gTlsqDcuVersion[100];
extern void SetTlsqDcuDebugLevel(TLSQ_DCU_DEBUG_LEVEL eLevel);
extern void PrintTlsqDcuDebug(TLSQ_DCU_DEBUG_LEVEL eLevel, const char *format, ...);

#define LOG_ERROR(fmt, args...) do {	\
		PrintTlsqDcuDebug(TLSQ_DCU_DEBUG_ERROR, "[%s:%d:%s] " fmt "\n", __FILE__, __LINE__, __FUNCTION__, ## args); \
	} while(0)

#define LOG_DEBUG(fmt, args...) do {	\
		PrintTlsqDcuDebug(TLSQ_DCU_DEBUG_DEBUG, "[%s:%d:%s] " fmt "\n", __FILE__, __LINE__, __FUNCTION__, ## args); \
	} while(0)

#define LOG_INFO(fmt, args...) do {	\
		PrintTlsqDcuDebug(TLSQ_DCU_DEBUG_INFO, "[%s:%d:%s] " fmt "\n", __FILE__, __LINE__, __FUNCTION__, ## args); \
	} while(0)

#ifdef __cplusplus
}
#endif

#endif // __TSLQ_DCU_LOGGER_H__

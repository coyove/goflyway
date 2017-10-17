/* Created by "go tool cgo" - DO NOT EDIT. */

/* package command-line-arguments */

/* Start of preamble from import "C" comments.  */


#line 3 "C:\\Go\\golib\\src\\github.com\\coyove\\goflyway\\shared\\main.go"

typedef void (*g_callback)();

static void invoke(g_callback f) { f(); }

#line 1 "cgo-generated-wrapper"


/* End of preamble from import "C" comments.  */


/* Start of boilerplate cgo prologue.  */
#line 1 "cgo-gcc-export-header-prolog"

#ifndef GO_CGO_PROLOGUE_H
#define GO_CGO_PROLOGUE_H

typedef signed char GoInt8;
typedef unsigned char GoUint8;
typedef short GoInt16;
typedef unsigned short GoUint16;
typedef int GoInt32;
typedef unsigned int GoUint32;
typedef long long GoInt64;
typedef unsigned long long GoUint64;
typedef GoInt64 GoInt;
typedef GoUint64 GoUint;
typedef __SIZE_TYPE__ GoUintptr;
typedef float GoFloat32;
typedef double GoFloat64;
typedef float _Complex GoComplex64;
typedef double _Complex GoComplex128;

/*
  static assertion to make sure the file is being used on architecture
  at least with matching size of GoInt.
*/
typedef char _check_for_64_bit_pointer_matching_GoInt[sizeof(void*)==64/8 ? 1:-1];

typedef struct { const char *p; GoInt n; } GoString;
typedef void *GoMap;
typedef void *GoChan;
typedef struct { void *t; void *v; } GoInterface;
typedef struct { void *data; GoInt len; GoInt cap; } GoSlice;

#endif

/* End of boilerplate cgo prologue.  */

#ifdef __cplusplus
extern "C" {
#endif


extern void GetNickname(char* p0);

extern void ManInTheMiddle(int p0);

extern long long unsigned int GetLastestLogIndex();

extern long long unsigned int ReadLog(long long unsigned int p0, char* p1);

extern void DeleteLogSince(long long unsigned int p0);

extern int StartServer(g_callback p0, char* p1, char* p2, char* p3, char* p4, char* p5, char* p6, char* p7, int p8, int p9, int p10, int p11);

extern void StopServer();

extern int SwitchProxyType(int p0);

#ifdef __cplusplus
}
#endif

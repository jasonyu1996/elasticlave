#ifndef __EDGE_SYSCALL_H_
#define __EDGE_SYSCALL_H_

#include "edge_common.h"
#include "syscall_nums.h"
#include "edge_call.h"
#include <sys/types.h>
#include <sys/stat.h>

#ifdef __cplusplus
extern "C" {
#endif


// Special call number
#define EDGECALL_SYSCALL MAX_EDGE_CALL+1

struct edge_syscall{
  size_t syscall_num;
  unsigned char data[];
};

typedef struct sargs_SYS_openat{
  int dirfd;
  int flags;
  int mode;
  char path[];
} sargs_SYS_openat;

// unlinkat uses (most) of the same args
typedef sargs_SYS_openat sargs_SYS_unlinkat;

typedef struct sargs_SYS_write{
  int fd;
  size_t len;
  unsigned char buf[];
} sargs_SYS_write;


typedef struct sargs_fast_SYS_write{
  int fd;
  size_t len;
  uid_t uid;
  uintptr_t offset;
} sargs_fast_SYS_write;

  // Read uses the same args as write
typedef sargs_SYS_write sargs_SYS_read;
typedef sargs_fast_SYS_write sargs_fast_SYS_read;

struct _sargs_fd_only{
  int fd;
};

typedef struct _sargs_fd_only sargs_SYS_fsync;
typedef struct _sargs_fd_only sargs_SYS_close;

typedef struct sargs_SYS_lseek{
  int fd;
  off_t offset;
  int whence;
} sargs_SYS_lseek;

typedef struct sargs_SYS_ftruncate{
  int fd;
  off_t offset;
} sargs_SYS_ftruncate;

typedef struct sargs_SYS_fstatat{
  int dirfd;
  int flags;
  struct stat stats;
  char pathname[];
} sargs_SYS_fstatat;

typedef struct {
  int* uaddr;
  int futex_op;
  int val;
  void* timeout;
  int* uaddr2;
  int val3;
} sargs_SYS_futex;

typedef struct {
  __clockid_t clock;
  struct timespec tp;
} sargs_SYS_clock_gettime;

#ifdef __cplusplus
}
#endif

#endif /* __EDGE_SYSCALL_H_ */

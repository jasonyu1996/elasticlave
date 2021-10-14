#ifdef FAST_IO_SYSCALL_WRAPPING
#ifndef _FAST_IO_WRAP_H_
#define _FAST_IO_WRAP_H_

#include <sys/uio.h>
#include <sys/types.h>
#include "edge_syscall.h"
#include "types.h"

uintptr_t fast_syscall_add_buf(uid_t uid);
uintptr_t fast_io_syscall_write(int fd, uid_t uid, size_t len, uintptr_t offset);
uintptr_t fast_io_syscall_read(int fd, uid_t uid, size_t len, uintptr_t offset);
#endif /* _IO_WRAP_H_ */
#endif /* IO_SYSCALL_WRAPPING */

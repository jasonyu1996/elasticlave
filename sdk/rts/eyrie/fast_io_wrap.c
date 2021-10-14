#ifdef FAST_IO_SYSCALL_WRAPPING
#include <stdint.h>
#include "fast_io_wrap.h"
#include <alloca.h>
#include "uaccess.h"
#include "syscall.h"
#include "string.h"
#include "edge_syscall.h"

extern struct shared_region shared_region;

/* Syscalls iozone uses in -i0 mode
*** Fake these
 *   uname
*** odd
    rt_sigaction
    rt_sigprocmask
*** hard
    brk
    mmap
*/

#define MAX_STRACE_PRINT 20

uintptr_t fast_syscall_add_buf(uid_t uid){
  struct edge_syscall* edge_syscall = (struct edge_syscall*)edge_call_data_ptr(&shared_region);
  uid_t* args = (uid_t*)edge_syscall->data;
  uintptr_t ret = -1;
  edge_syscall->syscall_num = FAST_SYSCALL_ADD_BUF;
  *args = uid; // no check for now

  size_t totalsize = (sizeof(struct edge_syscall) + sizeof(uid_t));

  ret = dispatch_edgecall_syscall(edge_syscall, totalsize);

  print_strace("[runtime] proxied read (size: %lu) = %li\r\n",len, ret);
  return ret;
}

uintptr_t fast_io_syscall_read(int fd, uid_t uid, uintptr_t offset, size_t len){
  struct edge_syscall* edge_syscall = (struct edge_syscall*)edge_call_data_ptr(&shared_region);
  sargs_fast_SYS_read* args = (sargs_fast_SYS_read*)edge_syscall->data;
  uintptr_t ret = -1;
  edge_syscall->syscall_num = SYS_read + FAST_SYSCALL_OFFSET;
  args->fd =fd;
  args->len = len;
  args->uid = uid; // no check for now
  args->offset = offset;

  size_t totalsize = (sizeof(struct edge_syscall) +
					  sizeof(sargs_fast_SYS_read));

  ret = dispatch_edgecall_syscall(edge_syscall, totalsize);

  print_strace("[runtime] proxied read (size: %lu) = %li\r\n",len, ret);
  return ret;
}


uintptr_t fast_io_syscall_write(int fd, uid_t uid, uintptr_t offset, size_t len){
  /* print_strace("[write] len :%lu\r\n", len); */
  /* if(len > 0){ */
  /*   size_t stracelen = len > MAX_STRACE_PRINT? MAX_STRACE_PRINT:len; */
  /*   char* lbuf[MAX_STRACE_PRINT+1]; */
  /*   memset(lbuf, 0, sizeof(lbuf)); */
  /*   copy_from_user(lbuf, (void*)buf, stracelen); */
  /*   print_strace("[write] \"%s\"\r\n", (char*)lbuf); */
  /* } */

  struct edge_syscall* edge_syscall = (struct edge_syscall*)edge_call_data_ptr(&shared_region);
  sargs_fast_SYS_write* args = (sargs_fast_SYS_write*)edge_syscall->data;
  uintptr_t ret = -1;

  edge_syscall->syscall_num = SYS_write + FAST_SYSCALL_OFFSET;
  args->fd =fd;
  args->len = len;
  args->uid = uid; // no check for now
  args->offset = offset;


  size_t totalsize = (sizeof(struct edge_syscall) +
					  sizeof(sargs_fast_SYS_write));

  ret = dispatch_edgecall_syscall(edge_syscall, totalsize);

  print_strace("[runtime] proxied write (size: %lu) = %li\r\n",len, ret);
  if(ret == -1){
	  printf("Error write: %lu\n", len);
	  while(1);
  }
  return ret;
}

/*uintptr_t fast_io_syscall_writev(int fd, const struct iovec *iov, int iovcnt){*/
  /*int i=0;*/
  /*uintptr_t ret = 0;*/
  /*size_t total = 0;*/
  /*print_strace("[runtime] Simulating writev (cnt %i) with write calls\r\n",iovcnt);*/
  /*for(i=0; i<iovcnt && ret >= 0;i++){*/
    /*struct iovec iov_local;*/
    /*copy_from_user(&iov_local, &(iov[i]), sizeof(struct iovec));*/
    /*ret = fast_io_syscall_write(fd,iov_local.iov_base, iov_local.iov_len);*/
    /*total += ret;*/
  /*}*/
  /*ret = total;*/
  /*print_strace("[runtime] Simulated writev = %li\r\n",ret);*/
  /*return ret;*/
/*}*/

/*uintptr_t fast_io_syscall_readv(int fd, const struct iovec *iov, int iovcnt){*/
  /*int i=0;*/
  /*uintptr_t ret = 0;*/
  /*size_t total = 0;*/
  /*print_strace("[runtime] Simulating readv (cnt %i) with read calls\r\n",iovcnt);*/
  /*for(i=0; i<iovcnt && ret >= 0;i++){*/
    /*struct iovec iov_local;*/
    /*copy_from_user(&iov_local, &(iov[i]), sizeof(struct iovec));*/
    /*ret = fast_io_syscall_read(fd, iov_local.iov_base, iov_local.iov_len);*/
    /*total += ret;*/
  /*}*/

  /*ret = total;*/
  /*print_strace("[runtime] Simulated readv = %li\r\n",ret);*/
  /*return ret;*/
/*}*/

#endif /* IO_SYSCALL_WRAPPING */

#include "incoming_syscall.h"
#include "edge_syscall.h"
#include "keystone.h"
#include <fcntl.h>
#include <unistd.h>
#include <linux/futex.h>
#include <cstdio>
#include <cerrno>
#include <cstdio>
#include <errno.h>
// Special edge-call handler for syscall proxying
void incoming_syscall(Keystone* enclave, struct edge_call* edge_call, struct shared_region* shared_region){
  struct edge_syscall* syscall_info;

  size_t args_size;

  if( edge_call_args_ptr(edge_call, (uintptr_t*)&syscall_info, &args_size, shared_region) != 0)
    goto syscall_error;

  // NOTE: Right now we assume that the args data is safe, even though
  // it may be changing under us. This should be safer in the future.

  edge_call->return_data.call_status = CALL_STATUS_OK;

  int64_t ret;
  sargs_SYS_openat* openat_args;
  sargs_SYS_unlinkat* unlinkat_args;
  sargs_SYS_ftruncate* ftruncate_args;
  sargs_SYS_write* write_args;
  sargs_SYS_read* read_args;
  sargs_SYS_fsync* fsync_args;
  sargs_SYS_close* close_args;
  sargs_SYS_lseek* lseek_args;
  sargs_SYS_futex* futex_args;
  sargs_SYS_clock_gettime* clock_gettime_args;
  sargs_fast_SYS_write* fast_write_args;
  sargs_fast_SYS_read* fast_read_args;
  sargs_SYS_fstatat* fstatat_args;
  uid_t buf_uid;
  void* buf;
  void* ret_data_ptr;
  int futex_idx;
  // Right now we only handle some io syscalls. See runtime for how
  // others are handled.
  switch(syscall_info->syscall_num){
#ifdef LINUX_SYSCALL_WRAPPING
  case(SYS_futex):;
	if(!enclave->futex_initialised){
		ret = -1;
		break;
	}
	futex_args = (sargs_SYS_futex*)syscall_info->data;
	
	futex_idx = (int*)futex_args->uaddr - (int*)enclave->in_enclave_shared_futex_start;
	pthread_mutex_lock(enclave->futex_mutex);
	enclave->local_futex_start[futex_idx] = enclave->shared_futex_start[futex_idx];
	pthread_mutex_unlock(enclave->futex_mutex);

	ret = syscall(SYS_futex, enclave->local_futex_start + futex_idx, futex_args->futex_op,
			futex_args->val, futex_args->timeout, futex_args->uaddr2,
			futex_args->val3);
	break;
#endif
  case(SYS_clock_gettime):;
    clock_gettime_args = (sargs_SYS_clock_gettime*)syscall_info->data;
	ret = clock_gettime(clock_gettime_args->clock, &clock_gettime_args->tp);

	break;
#ifdef IO_SYSCALL_WRAPPING
  case(SYS_openat):;
    openat_args = (sargs_SYS_openat*)syscall_info->data;
    ret = openat(openat_args->dirfd, openat_args->path,
                 openat_args->flags, openat_args->mode);
    break;
  case(SYS_unlinkat):;
    unlinkat_args = (sargs_SYS_unlinkat*)syscall_info->data;
    ret = unlinkat(unlinkat_args->dirfd, unlinkat_args->path,
                   unlinkat_args->flags);
    break;
  case(SYS_ftruncate):;
    ftruncate_args = (sargs_SYS_ftruncate*)syscall_info->data;
    ret = ftruncate(ftruncate_args->fd, ftruncate_args->offset);
    break;
  case(SYS_fstatat):;
    fstatat_args = (sargs_SYS_fstatat*)syscall_info->data;
    // Note the use of the implicit buffer in the stat args object (stats)
    ret = fstatat(fstatat_args->dirfd, fstatat_args->pathname,
                  &fstatat_args->stats, fstatat_args->flags);
    break;
  case(SYS_write):;
    write_args = (sargs_SYS_write*)syscall_info->data;
    ret = write(write_args->fd, write_args->buf, write_args->len);
    break;
  case(SYS_read):;
    read_args = (sargs_SYS_read*)syscall_info->data;
    ret = read(read_args->fd, read_args->buf, read_args->len);
    break;
  case(SYS_sync):;
    sync();
    ret = 0;
    break;
  case(SYS_fsync):;
    fsync_args = (sargs_SYS_fsync*)syscall_info->data;
    ret = fsync(fsync_args->fd);
    break;
  case(SYS_close):;
    close_args = (sargs_SYS_close*)syscall_info->data;
    ret = close(close_args->fd);
    break;
  case(SYS_lseek):;
    lseek_args = (sargs_SYS_lseek*)syscall_info->data;
    ret = lseek(lseek_args->fd, lseek_args->offset, lseek_args->whence);
    break;
#endif
#ifdef FAST_IO_SYSCALL_WRAPPING
  case(FAST_SYSCALL_ADD_BUF):
    buf_uid = *(uid_t*)syscall_info->data;
    buf = elasticlave_map(buf_uid);
    if(buf){
      enclave->add_region_buffer(buf_uid, buf);
      ret = 0;
    } else{
      ret = -1;
    }
    break;
  case(SYS_write + FAST_SYSCALL_OFFSET):;
    fast_write_args = (sargs_fast_SYS_write*)syscall_info->data;
    elasticlave_change(fast_write_args->uid, 9);
    //to get buf
    ret = write(fast_write_args->fd, 
        enclave->get_region_buffer(fast_write_args->uid) + fast_write_args->offset, 
        fast_write_args->len);
    elasticlave_change(fast_write_args->uid, 0);
    break;
  case(SYS_read + FAST_SYSCALL_OFFSET):;
    fast_read_args = (sargs_fast_SYS_read*)syscall_info->data;
    elasticlave_change(fast_read_args->uid, 11);
    ret = read(fast_read_args->fd,
        enclave->get_region_buffer(fast_read_args->uid) + fast_read_args->offset, 
        fast_read_args->len);
    elasticlave_change(fast_read_args->uid, 0);
    break;
#endif
  default:
    goto syscall_error;
  }

  /* Setup return value */
  ret_data_ptr = (void*)edge_call_data_ptr(shared_region);
  *(int64_t*)ret_data_ptr = ret;
  if(edge_call_setup_ret(edge_call, ret_data_ptr , sizeof(int64_t), shared_region) !=0) 
	  goto syscall_error;

  return;

 syscall_error:
  edge_call->return_data.call_status = CALL_STATUS_SYSCALL_FAILED;
  return;
}

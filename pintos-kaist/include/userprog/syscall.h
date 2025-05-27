#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);
void sys_exit(int);

struct lock filesys_lock;	// 파일 시스템 동기화용 전역 락

#endif /* userprog/syscall.h */

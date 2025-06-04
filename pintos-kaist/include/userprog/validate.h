#ifndef USERPROG_VALIDATE_H
#define USERPROG_VALIDATE_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#ifndef VM
void validate_ptr (const void *uaddr, size_t size);
#else
struct page *validate_ptr (const void *uaddr, size_t size);
#endif
void validate_str (const char *str);

int64_t get_user (const uint8_t *uaddr);
bool put_user (uint8_t *udst, uint8_t byte);

size_t copy_in (void *kernel_dst, const void *user_src, size_t size);
size_t copy_out (void *user_dst,   const void *kernel_src, size_t size);

#endif /* userprog/validate.h */
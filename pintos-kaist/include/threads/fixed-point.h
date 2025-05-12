#ifndef THREADS_FIXED_POINT_H
#define THREADS_FIXED_POINT_H

typedef int fixed_t;

#define F (1 << 14)

// 변환 함수
fixed_t int_to_fixed(int n);
int fixed_to_int(fixed_t x);
int fixed_to_int_round(fixed_t x);

// 연산 함수
fixed_t add_fixed(fixed_t x, fixed_t y);
fixed_t sub_fixed(fixed_t x, fixed_t y);
fixed_t mul_fixed(fixed_t x, fixed_t y);
fixed_t div_fixed(fixed_t x, fixed_t y);

fixed_t fixed_mul_int(fixed_t x, int n);
fixed_t fixed_div_int(fixed_t x, int n);

#endif
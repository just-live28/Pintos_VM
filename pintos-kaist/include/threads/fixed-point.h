#ifndef THREADS_FIXED_POINT_H
#define THREADS_FIXED_POINT_H

typedef int fixed_t;

#define SHIFT 14
#define F (1<<SHIFT)

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




fixed_t int_to_fixed(int n){
    return n << SHIFT;
}

//단순 버림
int fixed_to_int(fixed_t x){
    return x >> SHIFT;
}

//14번째 비트값 변동으로 반올림 구현
int fixed_to_int_round(fixed_t x){
    int a;
    if(x >= 0)
        a = x + (F>>1); // x + 0.5 
    else   
        a = x - (F>>1); // x - 0.5 
    return a >> SHIFT;
}

// 연산 함수
fixed_t add_fixed(fixed_t x, fixed_t y){
    return x + y;
}

fixed_t sub_fixed(fixed_t x, fixed_t y){
    return x - y;
}

fixed_t mul_fixed(fixed_t x, fixed_t y){
    return ((int64_t)x * y) >> SHIFT;
}
fixed_t div_fixed(fixed_t x, fixed_t y){
    return ((int64_t)x << SHIFT) / y;
}

fixed_t fixed_mul_int(fixed_t x, int n){
    return x * n;
}
fixed_t fixed_div_int(fixed_t x, int n){
    return x / n;
}


#endif
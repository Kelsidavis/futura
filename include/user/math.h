// SPDX-License-Identifier: MPL-2.0
// Minimal math.h — declares the float math functions third-party
// userland (libwayland fixed-point helpers) calls. Implementations
// live in libfutura/math.c if/when the call is actually exercised.

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#define M_PI       3.14159265358979323846
#define M_PI_2     1.57079632679489661923
#define M_E        2.7182818284590452354
#define HUGE_VAL   __builtin_huge_val()
#define HUGE_VALF  __builtin_huge_valf()
#define INFINITY   __builtin_inff()
#define NAN        __builtin_nanf("")

#define isnan(x)    __builtin_isnan(x)
#define isinf(x)    __builtin_isinf(x)
#define isfinite(x) __builtin_isfinite(x)

double fabs(double x);
double floor(double x);
double ceil(double x);
double round(double x);
double sqrt(double x);
double sin(double x);
double cos(double x);
double tan(double x);
double atan(double x);
double atan2(double y, double x);
double pow(double x, double y);
double exp(double x);
double log(double x);
double log2(double x);
double fmod(double x, double y);

float  fabsf(float x);
float  floorf(float x);
float  ceilf(float x);

#ifdef __cplusplus
}
#endif

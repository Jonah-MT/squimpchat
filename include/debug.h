#pragma once
#include <stdio.h>

#ifdef DEBUG
#define dbg_printf(...) (printf(__VA_ARGS__), fflush(stdout))
#else
#define dbg_printf(...) ((void)0)
#endif

#pragma once
#include <cstdint>
#include<ntifs.h>
#include<intrin.h>
#include<Ndis.h>
#include"ia32/ia32.h"
#include"ia32/ia32.hpp"



#define LOG(format,...)   \
(DbgPrintEx)(77,0,("LOG:"));   \
(DbgPrintEx)(77,0,(format),##__VA_ARGS__);   \
(DbgPrintEx)(77,0,("\r\n"))

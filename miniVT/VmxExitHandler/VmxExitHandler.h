#pragma once
#include"../kerneldef.h"
#include "../asm/ams.h"
typedef struct _GUEST_CONTEXT
{
	ULONG64 mRax;
	ULONG64 mRcx;
	ULONG64 mRdx;
	ULONG64 mRbx;
	ULONG64 mRsp;
	ULONG64 mRbp;
	ULONG64 mRsi;
	ULONG64 mRdi;
	ULONG64 mR8;
	ULONG64 mR9;
	ULONG64 mR10;
	ULONG64 mR11;
	ULONG64 mR12;
	ULONG64 mR13;
	ULONG64 mR14;
	ULONG64 mR15;
}GUEST_CONTEXT, * PGUEST_CONTEXT;
EXTERN_C void VmxExitHandler(PGUEST_CONTEXT context);

//事件处理
VOID VmxHandlerCpuid(PGUEST_CONTEXT context);
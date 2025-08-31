#pragma once
#include"../kerneldef.h"
#include "../asm/ams.h"
enum class CPUTYPE
{
	None,
	Intel,
	AMD

};


namespace query
{


	CPUTYPE QueryCpuType();
}


typedef struct _VMXCPU
{
	ULONG cpuNumber;
	ULONG isSuccessVmOn;
	PVOID VmonMemory;
	PHYSICAL_ADDRESS VmOnPhy;

	PVOID VmCsMemory;
	PHYSICAL_ADDRESS VmCsPhy;

	PVOID VmHostStackTop; //栈顶
	PVOID VmHostStackBase; //栈底

	PVOID VmMsrBitMap;
	PHYSICAL_ADDRESS VmMsrBitMapPhy;

	struct _VMX_MAMAGER_PAGE_ENTRY* eptVmx;
	union _VMX_EPTP* eptp;
}VMXCPU, * PVMXCPU;
extern VMXCPU vmxCpuEntrys[128];



namespace intel
{
	BOOLEAN InitVirtualization(); //遍历所有核心

	BOOLEAN VMXInit();//初始化vt
	BOOLEAN VMXInitVmOn(); //初始化VMON区
	BOOLEAN VMXInitVmcs();//初始化VMCS区
	namespace vmcs
	{
		void FullGdtDataItem(int index, short selector);
		ULONG64 VmxAdjustControlValue(ULONG64 Msr, ULONG64 Ctl);
		BOOLEAN VmxIsControlTure();


		VOID VMXInitGuestState(ULONG64 GuestRip, ULONG64 GuestRsp);
		VOID VMXInitHostState();
		VOID InitEntry();
		VOID InitExit();
		VOID VMXInitControl();
		//只读VM-exit信息区域
	}


	namespace utils
	{
		BOOLEAN IsSupportVmx(); //是否支持vmx
		PVMXCPU VmxGetCurrentEntry();//获取当前环境块
		VOID GetError();//获取错误码
		
	}
		
}


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

	PVOID VmHostStackTop; //ջ��
	PVOID VmHostStackBase; //ջ��

	PVOID VmMsrBitMap;
	PHYSICAL_ADDRESS VmMsrBitMapPhy;

	struct _VMX_MAMAGER_PAGE_ENTRY* eptVmx;
	union _VMX_EPTP* eptp;
}VMXCPU, * PVMXCPU;
extern VMXCPU vmxCpuEntrys[128];



namespace intel
{
	BOOLEAN InitVirtualization(); //�������к���

	BOOLEAN VMXInit();//��ʼ��vt
	BOOLEAN VMXInitVmOn(); //��ʼ��VMON��
	BOOLEAN VMXInitVmcs();//��ʼ��VMCS��
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
		//ֻ��VM-exit��Ϣ����
	}


	namespace utils
	{
		BOOLEAN IsSupportVmx(); //�Ƿ�֧��vmx
		PVMXCPU VmxGetCurrentEntry();//��ȡ��ǰ������
		VOID GetError();//��ȡ������
		
	}
		
}


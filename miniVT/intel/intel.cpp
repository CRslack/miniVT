#include"intel.h"

VMXCPU vmxCpuEntrys[128]{0};
CPUTYPE query::QueryCpuType()
{
	CPUID_EAX_00 cpu_eax_00{};
	__cpuid((int*)&cpu_eax_00, CPUID_SIGNATURE);

	if (
		cpu_eax_00.EbxValueGenu == UINT32_C(0x756e6547) &&      /* 'Genu' */
		cpu_eax_00.EdxValueInei == UINT32_C(0x49656e69) &&	   /* 'ineI' */
		cpu_eax_00.EcxValueNtel == UINT32_C(0x6c65746e)		   /* 'ntel' */
		)
	{
		/* 'GenuineIntel' */
		LOG(" CPUTYPE::Intel");
		return  CPUTYPE::Intel;
	}

	if (
		cpu_eax_00.EbxValueGenu == UINT32_C(0x68747541) && /* 'Auth' */
		cpu_eax_00.EdxValueInei == UINT32_C(0x69746e65) && /* 'enti' */
		cpu_eax_00.EcxValueNtel == UINT32_C(0x444d4163)	   /* 'dAMD' */
		)
	{	/* 'AuthenticAMD' */
		LOG(" CPUTYPE::AMD");
		return  CPUTYPE::AMD;
	}



	return CPUTYPE::None;

}

BOOLEAN intel::InitVirtualization()
{
	//dpc 也行
	for (size_t i = 0; i < KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS); i++)
	{
	
		KAFFINITY mask = (KAFFINITY)(1ULL << i);
		KAFFINITY oldAffinity = KeSetSystemAffinityThreadEx(mask);
		if (utils::IsSupportVmx())
		{
		

			VMXInit(); //启动vt
			
		}
		KeRevertToUserAffinityThreadEx(oldAffinity);  // 恢复原始亲和性
	

	}

	return TRUE;
}

BOOLEAN intel::VMXInit()
{

	CONTEXT cx{};
	RtlCaptureContext(&cx);
	//获取函数返回地址  //_AddressOfReturnAddress 
//	DbgBreakPoint();
	{
		PVMXCPU vmxCpu = utils::VmxGetCurrentEntry();
		if (vmxCpu->isSuccessVmOn)
		{
			LOG(" Guest rip");
			return true;
				
		}
	}

	VMXInitVmOn();
	VMXInitVmcs();

	vmcs::VMXInitGuestState(cx.Rip,cx.Rsp);
	vmcs::VMXInitHostState();
	vmcs::InitEntry();
	vmcs::InitExit();
	vmcs::VMXInitControl();
	

	PVMXCPU vmxCpu = utils::VmxGetCurrentEntry();
	vmxCpu->isSuccessVmOn = 1;

	int error = __vmx_vmlaunch();
	if (error)
	{
		utils::GetError();
	}

	return TRUE;
}

BOOLEAN intel::VMXInitVmOn()
{


	//初始化结构
	PVMXCPU vmxCpu = utils::VmxGetCurrentEntry();

	vmxCpu->cpuNumber = KeGetCurrentProcessorNumberEx(NULL);

	PHYSICAL_ADDRESS low, hei;
	low.QuadPart = 0;
	hei.QuadPart = MAXULONG64;
	vmxCpu->VmonMemory = MmAllocateContiguousMemorySpecifyCache(PAGE_SIZE, low, hei, low, MmCached);
	memset(vmxCpu->VmonMemory, 0, PAGE_SIZE);
	vmxCpu->VmOnPhy = MmGetPhysicalAddress(vmxCpu->VmonMemory);

	//开启CR4

	ULONG64 mcr4 = __readcr4();
	ULONG64 mcr0 = __readcr0();

	ULONG64 vcr00 = __readmsr(IA32_VMX_CR0_FIXED0);
	ULONG64 vcr01 = __readmsr(IA32_VMX_CR0_FIXED1);
	ULONG64 vcr40 = __readmsr(IA32_VMX_CR4_FIXED0);
	ULONG64 vcr41 = __readmsr(IA32_VMX_CR4_FIXED1);

	mcr0 |= vcr00;
	mcr0 &= vcr01;

	mcr4 |= vcr40;
	mcr4 &= vcr41;

	__writecr4(mcr4);
	__writecr0(mcr0);

	vmxCpu->isSuccessVmOn = 0;

	ULONG64 basic = __readmsr(IA32_VMX_BASIC);

	*(PULONG)vmxCpu->VmonMemory = (ULONG)basic;

	int error = __vmx_on((unsigned __int64*)&vmxCpu->VmOnPhy.QuadPart);

	DbgPrintEx(77, 0, "[db]:%s vmx_on err = %d\r\n", __FUNCTION__, error);


	if (error)
	{
	

	}
	else
	{
		vmxCpu->isSuccessVmOn = 1;
	}

	LOG("__vmx_on sucess");
	return error == 0;
}

BOOLEAN intel::VMXInitVmcs()
{
	PVMXCPU vmxCpu = utils::VmxGetCurrentEntry();

	PHYSICAL_ADDRESS low, hei;
	low.QuadPart = 0;
	hei.QuadPart = MAXULONG64;
	vmxCpu->VmHostStackTop = MmAllocateContiguousMemorySpecifyCache(PAGE_SIZE * 36, low, hei, low, MmCached);

	memset(vmxCpu->VmHostStackTop, 0, PAGE_SIZE * 36);

	vmxCpu->VmHostStackBase = (PVOID)((ULONG64)vmxCpu->VmHostStackTop + PAGE_SIZE * 35-sizeof(ULONG64));

	vmxCpu->VmCsMemory = MmAllocateContiguousMemorySpecifyCache(PAGE_SIZE, low, hei, low, MmCached);

	memset(vmxCpu->VmCsMemory, 0, PAGE_SIZE);

	vmxCpu->VmCsPhy = MmGetPhysicalAddress(vmxCpu->VmCsMemory);


	vmxCpu->VmMsrBitMap = MmAllocateContiguousMemorySpecifyCache(PAGE_SIZE, low, hei, low, MmCached);

	memset(vmxCpu->VmMsrBitMap, 0, PAGE_SIZE);

	vmxCpu->VmMsrBitMapPhy = MmGetPhysicalAddress(vmxCpu->VmMsrBitMap);



	//写入身份ID
	ULONG64 basic = __readmsr(IA32_VMX_BASIC);

	*(PULONG)vmxCpu->VmCsMemory = (ULONG)basic;


	int error = __vmx_vmclear((unsigned __int64*)&vmxCpu->VmCsPhy.QuadPart);
	if (error)
	{
		DbgPrintEx(77, 0, "[db]:%s __vmx_vmclear err = %d\r\n", __FUNCTION__, error);
		return FALSE;
	}

	error = __vmx_vmptrld((unsigned __int64*)&vmxCpu->VmCsPhy.QuadPart);

	if (error)
	{
		DbgPrintEx(77, 0, "[db]:%s __vmx_vmptrld err = %d\r\n", __FUNCTION__, error);
		return FALSE;
	}

	LOG("__vmx_vmptrld sucess");




	return TRUE;
}

BOOLEAN intel::utils::IsSupportVmx()
{
	//检查CPU是否支持VT
	CPUID_EAX_01 CpuInfo{};
	__cpuid((int*)&CpuInfo, CPUID_VERSION_INFORMATION);
	if (CpuInfo.CpuidFeatureInformationEcx.VirtualMachineExtensions != TRUE)  return FALSE;

	//检测BIOS是否开启了VT支持
	IA32_FEATURE_CONTROL_REGISTER FeatureControl{};
	FeatureControl.Flags = __readmsr(IA32_FEATURE_CONTROL);
	if (FeatureControl.LockBit != TRUE)   return FALSE;

	//VMX是否可以开启
	if (FeatureControl.EnableVmxOutsideSmx != TRUE)   return FALSE;

	//VT是否已经开启
	CR4  cr4{};
	cr4.Flags = __readcr4();
	if (cr4.VmxEnable)  return FALSE;;


	return TRUE;
}

PVMXCPU intel::utils::VmxGetCurrentEntry()
{
	ULONG number = KeGetCurrentProcessorNumberEx(NULL);

	return &vmxCpuEntrys[number];
}

VOID intel::utils::GetError()
{
	ULONG64 error_code;
	if (__vmx_vmread(VMCS_VM_INSTRUCTION_ERROR, &error_code) == 0) {	

		LOG("error:%d", error_code);
	}

}

void intel::vmcs::FullGdtDataItem(int index, short selector)
{
	segment_descriptor_register_64 gdtTable = { 0 };
	AsmGetGdtTable(&gdtTable);
	//00cf9300`0000ffff

	USHORT select = selector;
	selector &= 0xFFF8;

	ULONG64 limit = __segmentlimit(selector);
	PULONG item = (PULONG)(gdtTable.base_address + selector);

	LARGE_INTEGER itemBase = { 0 };
	itemBase.LowPart = (*item & 0xFFFF0000) >> 16;
	item += 1;
	itemBase.LowPart |= (*item & 0xFF000000) | ((*item & 0xFF) << 16);

	//属性
	ULONG attr = (*item & 0x00F0FF00) >> 8;



	if (selector == 0)
	{
		attr |= 1 << 16;
	}

	__vmx_vmwrite(VMCS_GUEST_ES_BASE + index * 2, itemBase.QuadPart);
	__vmx_vmwrite(VMCS_GUEST_ES_LIMIT + index * 2, limit);
	__vmx_vmwrite(VMCS_GUEST_ES_ACCESS_RIGHTS + index * 2, attr);
	__vmx_vmwrite(VMCS_GUEST_ES_SELECTOR + index * 2, select);
}

ULONG64 intel::vmcs::VmxAdjustControlValue(ULONG64 Msr, ULONG64 Ctl)
{
	LARGE_INTEGER MsrValue = { 0 };
	MsrValue.QuadPart = __readmsr(Msr);
	Ctl &= MsrValue.HighPart;     //前32位为0的位置表示那些必须设置位0
	Ctl |= MsrValue.LowPart;      //后32位为1的位置表示那些必须设置位1
	return Ctl;
}

BOOLEAN intel::vmcs::VmxIsControlTure()
{
	ULONG64 basic = __readmsr(IA32_VMX_BASIC);
	return ((basic >> 55) & 1);
}

VOID intel::vmcs::VMXInitGuestState(ULONG64 GuestRip, ULONG64 GuestRsp)
{
	PVMXCPU vmxCpu = utils::VmxGetCurrentEntry();

	FullGdtDataItem(0, AsmReadES());
	FullGdtDataItem(1, AsmReadCS());
	FullGdtDataItem(2, AsmReadSS());
	FullGdtDataItem(3, AsmReadDS());
	FullGdtDataItem(4, AsmReadFS());
	FullGdtDataItem(5, AsmReadGS());
	FullGdtDataItem(6, AsmReadLDTR());

	segment_descriptor_register_64 gdtTable = { 0 };
	AsmGetGdtTable(&gdtTable);


	ULONG trSelector = AsmReadTR();

	trSelector &= 0xFFF8;
	ULONG64 trlimit = __segmentlimit(trSelector);

	LARGE_INTEGER trBase = { 0 };

	PULONG trItem = (PULONG)(gdtTable.base_address + trSelector);


	//读TR
	trBase.LowPart = ((trItem[0] >> 16) & 0xFFFF) | ((trItem[1] & 0xFF) << 16) | ((trItem[1] & 0xFF000000));
	trBase.HighPart = trItem[2];

	//属性
	ULONG attr = (trItem[1] & 0x00F0FF00) >> 8;
	__vmx_vmwrite(GUEST_TR_BASE, trBase.QuadPart);
	__vmx_vmwrite(GUEST_TR_LIMIT, trlimit);
	__vmx_vmwrite(GUEST_TR_AR_BYTES, attr);
	__vmx_vmwrite(GUEST_TR_SELECTOR, trSelector);

	__vmx_vmwrite(GUEST_IA32_DEBUGCTL, __readmsr(IA32_DEBUGCTL));
	__vmx_vmwrite(GUEST_IA32_PAT, __readmsr(IA32_PAT));
	__vmx_vmwrite(GUEST_IA32_EFER, __readmsr(IA32_EFER));

	__vmx_vmwrite(GUEST_FS_BASE, __readmsr(IA32_FS_BASE));
	__vmx_vmwrite(GUEST_GS_BASE, __readmsr(IA32_GS_BASE));

	__vmx_vmwrite(GUEST_SYSENTER_CS, __readmsr(0x174));
	__vmx_vmwrite(GUEST_SYSENTER_ESP, __readmsr(0x175));
	__vmx_vmwrite(GUEST_SYSENTER_EIP, __readmsr(0x176));


	__vmx_vmwrite(GUEST_GDTR_BASE, gdtTable.base_address);
	__vmx_vmwrite(GUEST_GDTR_LIMIT, gdtTable.limit);

	//设置虚拟机第一次的返回地址与堆栈
	__vmx_vmwrite(GUEST_RSP, GuestRsp);
	__vmx_vmwrite(GUEST_RIP, GuestRip);

	segment_descriptor_register_64 idtTable = { 0 };
	__sidt(&idtTable);
	__vmx_vmwrite(GUEST_IDTR_BASE, idtTable.base_address);
	__vmx_vmwrite(GUEST_IDTR_LIMIT, idtTable.limit);

	__vmx_vmwrite(GUEST_CR0, __readcr0());
	__vmx_vmwrite(GUEST_CR4, __readcr4());
	__vmx_vmwrite(GUEST_CR3, __readcr3());
	__vmx_vmwrite(GUEST_RFLAGS, __readeflags());
	__vmx_vmwrite(GUEST_DR7, __readdr(7));

	__vmx_vmwrite(VMCS_LINK_POINTER, -1);

}

VOID intel::vmcs::VMXInitHostState()
{

	PVMXCPU vmxCpu = utils::VmxGetCurrentEntry();


	segment_descriptor_register_64 gdtTable = { 0 };
	AsmGetGdtTable(&gdtTable);


	ULONG trSelector = AsmReadTR();

	trSelector &= 0xFFF8;

	LARGE_INTEGER trBase = { 0 };

	PULONG trItem = (PULONG)(gdtTable.base_address + trSelector);


	//读TR
	trBase.LowPart = ((trItem[0] >> 16) & 0xFFFF) | ((trItem[1] & 0xFF) << 16) | ((trItem[1] & 0xFF000000));
	trBase.HighPart = trItem[2];

	//属性
	__vmx_vmwrite(HOST_TR_BASE, trBase.QuadPart);
	__vmx_vmwrite(HOST_TR_SELECTOR, trSelector);

	__vmx_vmwrite(HOST_ES_SELECTOR, AsmReadES() & 0xfff8);
	__vmx_vmwrite(HOST_CS_SELECTOR, AsmReadCS() & 0xfff8);
	__vmx_vmwrite(HOST_SS_SELECTOR, AsmReadSS() & 0xfff8);
	__vmx_vmwrite(HOST_DS_SELECTOR, AsmReadDS() & 0xfff8);
	__vmx_vmwrite(HOST_FS_SELECTOR, AsmReadFS() & 0xfff8);
	__vmx_vmwrite(HOST_GS_SELECTOR, AsmReadGS() & 0xfff8);



	__vmx_vmwrite(HOST_CR0, __readcr0());
	__vmx_vmwrite(HOST_CR4, __readcr4());
	__vmx_vmwrite(HOST_CR3, __readcr3());
	__vmx_vmwrite(HOST_RSP, (ULONG64)vmxCpu->VmHostStackBase);
	__vmx_vmwrite(HOST_RIP, (size_t)&AsmVmxExitHandler);


	__vmx_vmwrite(HOST_IA32_PAT, __readmsr(IA32_PAT));
	__vmx_vmwrite(HOST_IA32_EFER, __readmsr(IA32_EFER));
	//__vmx_vmwrite(HOST_IA32_PERF_GLOBAL_CTRL, __readmsr(IA32_PERF_GLOBAL_CTRL));

	__vmx_vmwrite(HOST_FS_BASE, __readmsr(IA32_FS_BASE)); 
	__vmx_vmwrite(HOST_GS_BASE, __readmsr(IA32_GS_BASE));

	__vmx_vmwrite(HOST_IA32_SYSENTER_CS, __readmsr(0x174));
	__vmx_vmwrite(HOST_IA32_SYSENTER_ESP, __readmsr(0x175));
	__vmx_vmwrite(HOST_IA32_SYSENTER_EIP, __readmsr(0x176));


	//IDT GDT

	segment_descriptor_register_64 idtTable;
	__sidt(&idtTable);

	__vmx_vmwrite(HOST_GDTR_BASE, gdtTable.base_address);
	__vmx_vmwrite(HOST_IDTR_BASE, idtTable.base_address);
}

VOID intel::vmcs::InitEntry()
{
	ia32_vmx_basic_register vBMsr{};
	vBMsr.flags = __readmsr(IA32_VMX_BASIC);

	ia32_vmx_entry_ctls_register entry{};
	entry.ia32e_mode_guest = 1;
	entry.flags = VmxAdjustControlValue(vBMsr.vmx_controls ? IA32_VMX_TRUE_ENTRY_CTLS : IA32_VMX_ENTRY_CTLS, entry.flags);
	__vmx_vmwrite(VMCS_CTRL_VMENTRY_CONTROLS, entry.flags);
	__vmx_vmwrite(VMCS_CTRL_VMENTRY_MSR_LOAD_COUNT, 0);
	__vmx_vmwrite(VMCS_CTRL_VMENTRY_INTERRUPTION_INFORMATION_FIELD, 0);
}

VOID intel::vmcs::InitExit()
{
	ia32_vmx_basic_register vBMsr{};
	vBMsr.flags = __readmsr(IA32_VMX_BASIC);

	ia32_vmx_exit_ctls_register exit{};
	exit.host_address_space_size = 1;
	exit.flags = VmxAdjustControlValue(vBMsr.vmx_controls ? IA32_VMX_TRUE_EXIT_CTLS : IA32_VMX_EXIT_CTLS, exit.flags);
	__vmx_vmwrite(VMCS_CTRL_VMEXIT_CONTROLS, exit.flags);
	__vmx_vmwrite(VMCS_CTRL_VMEXIT_MSR_LOAD_COUNT, 0);
	__vmx_vmwrite(VMCS_VMEXIT_INTERRUPTION_INFORMATION, 0);
}

VOID intel::vmcs::VMXInitControl()
{

	PVMXCPU vmxCpu =utils::VmxGetCurrentEntry();

	ULONG64 contorlmsr = VmxIsControlTure() ? 0x48D : 0x481;
	ULONG64 Proccontorlmsr = VmxIsControlTure() ? 0x48E : 0x482;

	ULONG mark = 0;
	ULONG64 msrValue = VmxAdjustControlValue( contorlmsr, mark);

	__vmx_vmwrite(PIN_BASED_VM_EXEC_CONTROL, msrValue);



	mark = 0x10000000 | 0x80000000;
	msrValue = VmxAdjustControlValue( Proccontorlmsr, mark);

	__vmx_vmwrite(CPU_BASED_VM_EXEC_CONTROL, msrValue);


	//VmxSetReadMsrBitMap(vmxCpu->VmMsrBitMap, 0xc0000082, TRUE);

	//__vmx_vmwrite(MSR_BITMAP, vmxCpu->VmMsrBitMapPhy.QuadPart);



	//扩展
	mark = 0x00100000 | 0x00000008 | 0x00001000;


	//if (VmxEptInit())
	//{
	//	//mark |= SECONDARY_EXEC_ENABLE_VPID | SECONDARY_EXEC_ENABLE_EPT;
	//	//__vmx_vmwrite(VIRTUAL_PROCESSOR_ID, vmxCpu->cpuNumber + 1);
	//	mark |= SECONDARY_EXEC_ENABLE_EPT;
	//	__vmx_vmwrite(EPT_POINTER, vmxCpu->eptp->Flags);
	//}
	msrValue = VmxAdjustControlValue( 0x48B, mark);
	__vmx_vmwrite(SECONDARY_VM_EXEC_CONTROL, msrValue);
}

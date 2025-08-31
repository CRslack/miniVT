#include "VmxExitHandler.h"
ULONG64 VmxReadField(ULONG64 idField)
{
	ULONG64 value = 0;
	__vmx_vmread(idField, &value);

	return value;
}


void VmxExitHandler(PGUEST_CONTEXT context)
{
	ULONG64 reason = VmxReadField(VMCS_EXIT_REASON); //ÍË³öÔ­Òò
	ULONG64 guestRip = VmxReadField(VMCS_GUEST_RIP); 
	ULONG64 guestRsp = VmxReadField(VMCS_GUEST_RSP);
	ULONG64 codelen = VmxReadField(VMCS_VMEXIT_INSTRUCTION_LENGTH); 

	ULONG mreason = reason & 0xFFFF;

	//DbgBreakPoint();
	LOG("mreason %d %x", mreason);
	switch (mreason)
	{
	case VMX_EXIT_REASON_EXCEPTION_OR_NMI:
	{
	
		break;
	}
	case VMX_EXIT_REASON_EXECUTE_CPUID:
	{
		VmxHandlerCpuid(context);
		break;
	}


	case VMX_EXIT_REASON_EXECUTE_RDMSR:
	{

		LARGE_INTEGER msr;
		msr.QuadPart = __readmsr(context->mRcx);
		context->mRax = msr.LowPart;
		context->mRdx = msr.HighPart;
		break;
	}
	case VMX_EXIT_REASON_EXECUTE_WRMSR:
	{


		LARGE_INTEGER msr;
		msr.LowPart = context->mRax;
		msr.HighPart = context->mRdx;
		__writemsr(context->mRcx,msr.QuadPart);
		break;
	}

	}

	__vmx_vmwrite(VMCS_GUEST_RIP, guestRip + codelen);
	__vmx_vmwrite(VMCS_GUEST_RSP, guestRsp);


}

VOID VmxHandlerCpuid(PGUEST_CONTEXT context)
{
	ULONG64 functionNumber = context->mRax;
	ULONG64 leaf = context->mRcx;


	int cpuinfo[4] = { 0 };
	__cpuidex(cpuinfo, functionNumber, leaf);
	context->mRax = cpuinfo[0];
	context->mRbx = cpuinfo[1];
	context->mRcx = cpuinfo[2];
	context->mRdx = cpuinfo[3];

}

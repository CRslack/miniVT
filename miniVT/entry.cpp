#include"kerneldef.h"
#include"intel/intel.h"



EXTERN_C VOID DriverUnload(PDRIVER_OBJECT pDriver)
{

	LOG("DriverUnload");
}

EXTERN_C NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	//Çý¶¯Èë¿Ú
	DriverObject->DriverUnload = DriverUnload;
	LOG("DriverEntry");

	switch (query::QueryCpuType())
	{
	case CPUTYPE::Intel:
	{
		intel::InitVirtualization();
		break;
	}
	default:
		break;
	}


	return STATUS_SUCCESS;
}
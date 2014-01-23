#include "ntddk.h"
#include "ntifs.h"
#include "declarations.h"
#include <stdlib.h>

#define IOCTL_SETEVENTS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_IN_DIRECT, FILE_READ_DATA | FILE_WRITE_DATA)
#define IOCTL_QUERYREQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_IN_DIRECT, FILE_READ_DATA | FILE_WRITE_DATA)
#define IOCTL_DESTROYEVENTS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_IN_DIRECT, FILE_READ_DATA | FILE_WRITE_DATA)

// todo: add MDL globals to device extension
// todo: 'formalise' debug output
// todo: fix debug output of zwTerminateProcess hook(currently outputs (null)

PMDL mdlSysCall;
PVOID *MappedSystemCallTable;

typedef struct _DEVICE_EXTENSION {
	PKEVENT pUserEvent; // user-mode notification event
	PKEVENT pKernelEvent; // kernel-mode notification event
	KSPIN_LOCK lockBusy;
	UNICODE_STRING usKeyPath;
	BOOLEAN bAllowCreateKey;
} DEVICE_EXTENSION, *PDEVICE_EXTENSION;

typedef NTSTATUS (*ZWCREATEKEY)	(OUT PHANDLE KeyHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes, IN ULONG  TitleIndex, IN PUNICODE_STRING  Class  OPTIONAL, IN ULONG  CreateOptions, OUT PULONG  Disposition  OPTIONAL);
//typedef NTSTATUS (*ZWTERMINATEPROCESS) (IN HANDLE  ProcessHandle, IN NTSTATUS  ExitStatus);

ZWCREATEKEY OldZwCreateKey;
//ZWTERMINATEPROCESS OldZwTerminateProcess;

/* --------------------FIX ME-----------------------
NTSTATUS NewZwTerminateProcess(IN HANDLE ProcessHandle, IN NTSTATUS ExitStatus)
{
	NTSTATUS ntStatus = STATUS_SUCCESS;
	PFILE_OBJECT pfHandleObj;
	POBJECT_NAME_INFORMATION pobjNameInfo;
	UNICODE_STRING usProcessName;
	ULONG ulRet;
	
	if(ProcessHandle){
		ntStatus = ObReferenceObjectByHandle(ProcessHandle, FILE_ALL_ACCESS, NULL, KernelMode, &pfHandleObj, NULL);
		if(NT_SUCCESS(ntStatus)){
			pobjNameInfo = NULL;
			ntStatus = ObQueryNameString(pfHandleObj, pobjNameInfo, 0, &ulRet);
			if(ntStatus == STATUS_INFO_LENGTH_MISMATCH){
				pobjNameInfo = ExAllocatePool(NonPagedPool, ulRet);
				if(pobjNameInfo)
					ntStatus = ObQueryNameString(pfHandleObj, pobjNameInfo, ulRet, &ulRet);
			}
			
			if(NT_SUCCESS(ntStatus)){
				RtlInitUnicodeString(&usProcessName, L"explorer.exe");
				
				if(!RtlCompareUnicodeString(&usProcessName, &pobjNameInfo->Name, FALSE))
					ntStatus = STATUS_ACCESS_DENIED;
				else
					ntStatus = STATUS_SUCCESS;
			}else
				DbgPrint("ObQueryNameString failed\n");
			
			if(pobjNameInfo)
				ExFreePool(pobjNameInfo);
		
			ObDereferenceObject(pfHandleObj);
		}else{
			DbgPrint("ObReferenceObjectByHandle failed\n");
			ntStatus = ((ZWTERMINATEPROCESS)(OldZwTerminateProcess)) (ProcessHandle, ExitStatus);
		}
	}
	
	if(ntStatus == STATUS_SUCCESS){
		ntStatus = ((ZWTERMINATEPROCESS)(OldZwTerminateProcess)) (ProcessHandle, ExitStatus);
	}
	
	return ntStatus;
}*/
		
NTSTATUS NewZwCreateKey(OUT PHANDLE KeyHandle, IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes, IN ULONG TitleIndex, IN PUNICODE_STRING Class OPTIONAL,
	IN ULONG CreateOptions, OUT PULONG Disposition OPTIONAL)
{
	NTSTATUS ntStatus = STATUS_SUCCESS;
	UNICODE_STRING usObjName, usPathName, usPipe;//, usProcessName;
	PFILE_OBJECT pFileObj, pfHandleObj;
	POBJECT_NAME_INFORMATION pobjNameInfo;
	PDEVICE_OBJECT pDeviceObj;
	PDEVICE_EXTENSION pDevExtension;
	PEPROCESS peProcess;
	KIRQL lockIRQL;
	ULONG ulRet;
	
	peProcess = IoGetCurrentProcess();
	
	//DbgPrint("\n\nAttempt to create registry key:\n\t%.16s: %wZ\n", peProcess->ImageFileName, ObjectAttributes->ObjectName);
	
	RtlInitUnicodeString(&usObjName, L"\\DosDevices\\ioCtl");
	RtlInitUnicodeString(&usPathName, L"New Key #1");	
	
	ntStatus = IoGetDeviceObjectPointer(&usObjName, FILE_ALL_ACCESS, &pFileObj, &pDeviceObj);
	if(NT_SUCCESS(ntStatus)){
		pDevExtension = (PDEVICE_EXTENSION)pDeviceObj->DeviceExtension;
		if( !pDevExtension->pKernelEvent || !pDevExtension->pUserEvent ||
		    RtlCompareUnicodeString(ObjectAttributes->ObjectName, &usPathName, FALSE) ){
			
			ObDereferenceObject(pFileObj);
			ntStatus = ((ZWCREATEKEY)(OldZwCreateKey))
			(KeyHandle, DesiredAccess, ObjectAttributes, TitleIndex, Class, CreateOptions, Disposition);
			DbgPrint("\nNo match... Key creation allowed!\n");
			return ntStatus;
		}
		
		KeAcquireSpinLock(&pDevExtension->lockBusy, &lockIRQL);
		
		//----refrence handle to get full key path-----
		if(ObjectAttributes->RootDirectory){
			ntStatus = ObReferenceObjectByHandle(ObjectAttributes->RootDirectory, FILE_ALL_ACCESS, NULL, KernelMode, &pfHandleObj, NULL);
			if(NT_SUCCESS(ntStatus)){
				pobjNameInfo = NULL;
				ntStatus = ObQueryNameString(pfHandleObj, pobjNameInfo, 0, &ulRet);
				if(ntStatus == STATUS_INFO_LENGTH_MISMATCH){
					pobjNameInfo = ExAllocatePool(NonPagedPool, ulRet);
					if(pobjNameInfo)
						ntStatus = ObQueryNameString(pfHandleObj, pobjNameInfo, ulRet, &ulRet);
				}
				
				if(NT_SUCCESS(ntStatus)){
					//mbstowcs(&wcProcessName, peProcess->ImageFileName, (strlen(peProcess->ImageFileName) + 5));
					//RtlInitUnicodeString(&usProcessName, &wcProcessName);
					RtlInitUnicodeString(&usPipe, L"|");
					
					pDevExtension->usKeyPath.Length = 0;
					pDevExtension->usKeyPath.MaximumLength = (pobjNameInfo->Name.Length +
						(usPipe.Length * 3) + ObjectAttributes->ObjectName->Length + peProcess->SeAuditProcessCreationInfo.ImageFileName->Name.MaximumLength);
					
					//DbgPrint("%d %d %d %d\n", 
					//	pobjNameInfo->Name.Length, usPipe.Length, ObjectAttributes->ObjectName->Length, usProcessName.Length);
					
					pDevExtension->usKeyPath.Buffer = ExAllocatePool(NonPagedPool, pDevExtension->usKeyPath.MaximumLength);
					if(pDevExtension->usKeyPath.Buffer){
						RtlCopyUnicodeString(&pDevExtension->usKeyPath, &pobjNameInfo->Name);
						RtlAppendUnicodeStringToString(&pDevExtension->usKeyPath, &usPipe);
						RtlAppendUnicodeStringToString(&pDevExtension->usKeyPath, ObjectAttributes->ObjectName);
						RtlAppendUnicodeStringToString(&pDevExtension->usKeyPath, &usPipe);
						//RtlAppendUnicodeStringToString(&pDevExtension->usKeyPath, &usProcessName);
						RtlAppendUnicodeStringToString(&pDevExtension->usKeyPath, &peProcess->SeAuditProcessCreationInfo.ImageFileName->Name);
						RtlAppendUnicodeStringToString(&pDevExtension->usKeyPath, &usPipe);
					}
				}else
					DbgPrint("\nObQueryNameString() failed\n");
				
				if(pobjNameInfo)
					ExFreePool(pobjNameInfo);
				
				ObDereferenceObject(pfHandleObj);
			}else
				DbgPrint("\nObReferenceObjectByHandle failed, ret = 0x%08x\n", ntStatus);
		}else{
			DbgPrint("\nObjectAttributes->RootDirectory = null\n");
			pDevExtension->usKeyPath.Length = 0;
			pDevExtension->usKeyPath.MaximumLength = ObjectAttributes->ObjectName->MaximumLength;
			pDevExtension->usKeyPath.Buffer = ExAllocatePool(NonPagedPool, pDevExtension->usKeyPath.MaximumLength);
			if(pDevExtension->usKeyPath.Buffer)
				RtlCopyUnicodeString(&pDevExtension->usKeyPath, ObjectAttributes->ObjectName);
		}
		//-----------
		
		// wait for usermode app to finish reading data
		KeSetEvent(pDevExtension->pKernelEvent, 0, TRUE);
		KeWaitForSingleObject(pDevExtension->pUserEvent, Executive, KernelMode, FALSE, NULL);
		
		KeResetEvent(pDevExtension->pKernelEvent);
		KeResetEvent(pDevExtension->pUserEvent);
		
		// wait for user response(allow, deny)
		KeWaitForSingleObject(pDevExtension->pUserEvent, Executive, KernelMode, FALSE, NULL);
		ntStatus = (pDevExtension->bAllowCreateKey == TRUE) ? STATUS_SUCCESS : STATUS_ACCESS_DENIED;

		//----cleanup----
		if(pDevExtension->usKeyPath.Buffer)
			ExFreePool(pDevExtension->usKeyPath.Buffer);
		KeReleaseSpinLock(&pDevExtension->lockBusy, lockIRQL);
		ObDereferenceObject(pFileObj);
	}
	
	if(ntStatus == STATUS_SUCCESS){
		ntStatus = ((ZWCREATEKEY)(OldZwCreateKey))
			(KeyHandle, DesiredAccess, ObjectAttributes, TitleIndex, Class, CreateOptions, Disposition);
		DbgPrint("\nKey creation allowed!\n");
	}else 
		DbgPrint("\nKey creation denied!\n");
	
	return ntStatus;
}

NTSTATUS DriverRead(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	NTSTATUS ntStatus = STATUS_SUCCESS;
    PIO_STACK_LOCATION pIoStackIrp = NULL;
	PDEVICE_EXTENSION pDevExtension;
	ANSI_STRING asString;
	PVOID pBuffer;
	ULONG dwLength = 0;
	
	DbgPrint("IRP_MJ_READ recevied\n");
    
	pDevExtension = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;
	pIoStackIrp = IoGetCurrentIrpStackLocation(Irp);
    
	ntStatus = RtlUnicodeStringToAnsiString(&asString, &pDevExtension->usKeyPath, TRUE);
	if(NT_SUCCESS(ntStatus)){
		dwLength = (asString.Length + 1);
		if(pIoStackIrp && Irp->MdlAddress && pIoStackIrp->Parameters.Read.Length >= dwLength){
			pBuffer = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);
			if(pBuffer){  
				RtlZeroMemory(pBuffer, dwLength);
				RtlCopyMemory(pBuffer, asString.Buffer, asString.Length);
				ntStatus = STATUS_SUCCESS;
			}else{
				DbgPrint("MmGetSystemAddressForMdlSafe failed!\n");
				ntStatus = STATUS_UNSUCCESSFUL;
			}
        }else{
			ntStatus = STATUS_BUFFER_TOO_SMALL;
		}
		RtlFreeAnsiString(&asString);
    }else{
		DbgPrint("RtlUnicodeStringToAnsiString failed!\n");
		ntStatus = STATUS_UNSUCCESSFUL;
	}
	
	Irp->IoStatus.Information = dwLength;
	Irp->IoStatus.Status = ntStatus;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return ntStatus;
}

NTSTATUS DriverIrpUnsupported(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	/*
	PIO_STACK_LOCATION pIoStackIrp;
	pIoStackIrp = IoGetCurrentIrpStackLocation(Irp);
	
	DbgPrint("\nUnsupported IRP recevied: %02X:%02X\n", pIoStackIrp->MajorFunction, pIoStackIrp->MinorFunction);
	*/
	return STATUS_NOT_SUPPORTED;
}

NTSTATUS DriverIoCtl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	NTSTATUS ntStatus = STATUS_SUCCESS;
	PIO_STACK_LOCATION pIoStackIrp;
	PDEVICE_EXTENSION pDevExtension;
	
	DbgPrint("IO Control recevied\n");
	
	pDevExtension = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;
	pIoStackIrp	  = IoGetCurrentIrpStackLocation(Irp);
	
	if(pIoStackIrp){
		switch(pIoStackIrp->Parameters.DeviceIoControl.IoControlCode)
		{
			case IOCTL_SETEVENTS: // obtains handle's to created from user-mode
			{
				DbgPrint("IOCTL_SETEVENTS received\n");
				if(pIoStackIrp->Parameters.DeviceIoControl.InputBufferLength == (sizeof(HANDLE) * 2)){
					PHANDLE pHandle = (PHANDLE)Irp->AssociatedIrp.SystemBuffer;
					if(pHandle){
						ntStatus = ObReferenceObjectByHandle(pHandle[0], 0, NULL,
									UserMode, &pDevExtension->pUserEvent, NULL);
						if(ntStatus != STATUS_SUCCESS){
							DbgPrint("Could not obtain handle to pUserEvent\n");
							ntStatus = STATUS_UNSUCCESSFUL;
							break;
						}
						
						ntStatus = ObReferenceObjectByHandle(pHandle[1], 0, NULL,
									UserMode, &pDevExtension->pKernelEvent, NULL);
						if(ntStatus != STATUS_SUCCESS){
							ObDereferenceObject(pDevExtension->pUserEvent);
							DbgPrint("Could not obtain handle to pKernelEvent\n");
							ntStatus = STATUS_UNSUCCESSFUL;
							break;
						}
						KeResetEvent(pDevExtension->pKernelEvent);
						KeResetEvent(pDevExtension->pUserEvent);
						DbgPrint("Event objects obtained successfully\n");
					}else DbgPrint("Failed pHandle invalid\n");
				}
				else DbgPrint("Failed BufferLength: %d\n",
					pIoStackIrp->Parameters.DeviceIoControl.InputBufferLength);
				break;
			}
			
			case IOCTL_QUERYREQUEST:
			{
				DbgPrint("IOCTL_QUERYREQUEST received\n");
				if(pIoStackIrp->Parameters.DeviceIoControl.InputBufferLength == sizeof(BOOLEAN)){
					BOOLEAN *bAllow = (BOOLEAN *)Irp->AssociatedIrp.SystemBuffer;
					if(bAllow){
						DbgPrint("nAllow = %d\n", *bAllow);
						pDevExtension->bAllowCreateKey = *bAllow;
						KeSetEvent(pDevExtension->pUserEvent, 0, FALSE);
					}else{
						ntStatus = STATUS_UNSUCCESSFUL;
					}
				}else{
					DbgPrint("IOCTL_QUERYREQUEST Failed, BufferLength: %d should be %d\n",
						pIoStackIrp->Parameters.DeviceIoControl.InputBufferLength, sizeof(BOOLEAN));
					ntStatus = STATUS_BUFFER_TOO_SMALL;
				}
				break;
			}
		
			case IOCTL_DESTROYEVENTS:
			{
				DbgPrint("IOCTL_DESTROYEVENTS received\n");
				if(pDevExtension->pUserEvent){
					ObDereferenceObject(pDevExtension->pUserEvent);
					pDevExtension->pUserEvent = NULL;
				}
				if(pDevExtension->pKernelEvent){ 
					ObDereferenceObject(pDevExtension->pKernelEvent);
					pDevExtension->pKernelEvent = NULL;
				}
				break;
			}
		}
	}
	
	Irp->IoStatus.Information = pIoStackIrp->Parameters.DeviceIoControl.InputBufferLength;
	Irp->IoStatus.Status = ntStatus;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);	
	return ntStatus;
}
	
VOID OnUnload(IN PDRIVER_OBJECT DriverObject)
{
	UNICODE_STRING usDosDriverName;
	PDEVICE_EXTENSION pDevExtension;
	
	DbgPrint("Unloading\n");
	pDevExtension = (PDEVICE_EXTENSION)DriverObject->DeviceObject->DeviceExtension;
	
	if(pDevExtension->pUserEvent){
		ObDereferenceObject(pDevExtension->pUserEvent);
		pDevExtension->pUserEvent = NULL;
	}
	if(pDevExtension->pKernelEvent){ 
		ObDereferenceObject(pDevExtension->pKernelEvent);
		pDevExtension->pKernelEvent = NULL;
	}
	
	UNHOOK_SYSCALL(ZwCreateKey, OldZwCreateKey, NewZwCreateKey);
	DbgPrint("ZwCreateKey unhooked\n");
	
	//UNHOOK_SYSCALL(ZwTerminateProcess, OldZwTerminateProcess, NewZwTerminateProcess);
	//DbgPrint("ZwTerminateProcess unhooked\n");
	
	if(mdlSysCall){
		MmUnmapLockedPages(MappedSystemCallTable, mdlSysCall);
		IoFreeMdl(mdlSysCall);	
	}
	
	RtlInitUnicodeString(&usDosDriverName, L"\\DosDevices\\ioCtl"); 
	IoDeleteSymbolicLink(&usDosDriverName);
	IoDeleteDevice(DriverObject->DeviceObject);
	return;
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
{
	NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
	PDEVICE_OBJECT pDevice;
	UNICODE_STRING usDriverName, usDosDriverName;
	unsigned int i = 0;

	DriverObject->DriverUnload = OnUnload;
	
	// make ssdt writable...
	mdlSysCall = MmCreateMdl(NULL, 
					KeServiceDescriptorTable->ServiceTable, 
					KeServiceDescriptorTable->TableSize * 4);
	if(!mdlSysCall){
		DbgPrint("MDL could not be created\n");
		return STATUS_UNSUCCESSFUL;
	}
	
	MmBuildMdlForNonPagedPool(mdlSysCall);
	mdlSysCall->MdlFlags = mdlSysCall->MdlFlags | MDL_MAPPED_TO_SYSTEM_VA;
	
	MappedSystemCallTable = MmMapLockedPages(mdlSysCall, KernelMode);
	DbgPrint("SSDT writable\n");
	
	RtlInitUnicodeString(&usDriverName, L"\\Device\\ioCtl");
	RtlInitUnicodeString(&usDosDriverName, L"\\DosDevices\\ioCtl"); 
	ntStatus = IoCreateDevice(DriverObject, sizeof(DEVICE_EXTENSION), &usDriverName,
							FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN,
							FALSE, &pDevice);
	
	if(NT_SUCCESS(ntStatus)){
		DbgPrint("Driver handle created successfully\n");
		
		for(i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
			DriverObject->MajorFunction[i] = DriverIrpUnsupported;
		
		RtlZeroMemory(pDevice->DeviceExtension, sizeof(DEVICE_EXTENSION));
		KeInitializeSpinLock(&((PDEVICE_EXTENSION)pDevice->DeviceExtension)->lockBusy);

		DriverObject->MajorFunction[IRP_MJ_READ]		   = DriverRead;
		DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverIoCtl;
		
		ntStatus = IoCreateSymbolicLink(&usDosDriverName, &usDriverName);
		if(!NT_SUCCESS(ntStatus)){
			DbgPrint("Could not create Symbolic link");
		}
		
		pDevice->Flags &= ~DO_DEVICE_INITIALIZING; 	
		pDevice->Flags |= DO_DIRECT_IO;
		
		OldZwCreateKey = (ZWCREATEKEY)( SYSTEMSERVICE(ZwCreateKey) );
		//OldZwTerminateProcess = (ZWTERMINATEPROCESS)( SYSTEMSERVICE(ZwTerminateProcess) );
		
		HOOK_SYSCALL(ZwCreateKey, NewZwCreateKey, OldZwCreateKey);
		DbgPrint("ZwCreateKey hooked\n");
		//HOOK_SYSCALL(ZwTerminateProcess, NewZwTerminateProcess, OldZwTerminateProcess);
		//DbgPrint("ZwTerminateProcess hooked\n");
		
	}
	
	return ntStatus;
}

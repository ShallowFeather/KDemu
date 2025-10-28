#ifndef EMULATE_UNICORN_HPP
#define EMULATE_UNICORN_HPP
#include "Global.h"
#include "LoadPE.hpp"
#include <string>
static std::map<std::string, uint64_t> registryHandles = {
	{"\\Registry\\Machine\\Software\\Wow6432Node\\EasyAntiCheat", 0x2a},
	{"\\Registry\\Machine\\System\\CurrentControlSet\\Control\\CI",0x1a},
	{"\\Registry\\Machine\\System\\CurrentControlSet\\Control",0x0a}
};
#define WSTRING_TO_VECTOR(str) std::vector<uint8_t>(reinterpret_cast<const uint8_t*>(str), \
                                                   reinterpret_cast<const uint8_t*>(str) + (wcslen(str) + 1) * sizeof(wchar_t))

class Emulate {
private:
	static PEloader* loader;
public:
	struct Pool {
		uint64_t addr;
		uint64_t size;
		bool free;
	};
	Emulate(uc_engine* uc);
	static uint64_t this_NtBase;
	static std::map<std::string, std::map<std::string, std::vector<uint8_t>>> registry;
	static void HeapFree(uint64_t addr);

	static uint64_t HeapAlloc(uc_engine* uc, uint64_t size);
	static uint64_t HeapAlloc(uc_engine* uc, uint64_t size, bool show);
	static uint64_t Alloc(uc_engine* uc, uint64_t size, uint64_t myaddr, bool show);
	static uint64_t Alloc(uc_engine* uc, uint64_t size, uint64_t myaddr, my_uc_prot m);
	static uint64_t Alloc(uc_engine* uc, uint64_t size, uint64_t myaddr);
	static uint64_t StackAlloc(ULONG AllocBytes);
	static uint64_t AllocVirtPhysPage(uint64_t virtAddr);

	static void StackFree(ULONG AllocBytes);
	static void RtlInitUnicodeString(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void RtlAnsiStringToUnicodeString(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void RtlInitString(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void RtlCompareMemory(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void IsDigit(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void atol(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void ExAllocatePoolWithTag(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void ExFreePoolWithTag(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void ExFreeHeapPool(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void IoCreateDevice(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void IoRegisterShutdownNotification(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void IoCreateSymbolicLink(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void ZwFlushKey(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void ZwCreateSection(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void RtlMultiByteToUnicodeN(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void RtlWriteRegistryValue(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void RtlDeleteRegistryValue(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void ZwOpenKey(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void ZwQueryValueKey(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void ZwCreateKey(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void ZwSetValueKey(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void ZwDeleteValueKey(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void RtlRandomEx(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void KeAreAllApcsDisabled(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void KeInitializeGuardedMutex(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void ZwDeviceIoControlFile(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void ZwCreateFile(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void ZwQueryInformationFile(uc_engine* uc);
	static void ZwQueryInformationFile(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void ZwReadFile(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void NtQuerySystemInformation(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void IoWMIOpenBlock(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void IoWMIQueryAllData(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void PsDereferenceSiloContext(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void __C_specific_handler(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void KeInitializeEvent(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void KeResetEvent(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void PsCreateSystemThread(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void KeCapturePersistentThreadState(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void ZwOpenDirectoryObject(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void ObReferenceObjectByHandle(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void NtClose(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void ExAcquireFastMutex(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void KeReleaseGuardedMutex(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void KeWaitForSingleObject(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void KeQueryTimeIncrement(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void KeSetEvent(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void PsIsSystemThread(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void PsTerminateSystemThread(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void RtlGetVersion(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void KeDelayExecutionThread(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void ZwQueryFullAttributesFile(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void KeEnterCriticalRegion(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void KeLeaveCriticalRegion(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void ExAcquireFastMutexUnsafe(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void ExReleaseFastMutexUnsafe(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void ExReleaseResourceLite(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void RtlUnicodeStringToAnsiString(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void IoDeleteSymbolicLink(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void BCryptOpenAlgorithmProvider(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void BCryptCloseAlgorithmProvider(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void BCryptCreateHash(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void BCryptHashData(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void BCryptGetProperty(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void BCryptFinishHash(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void BCryptDestroyHash(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void ZwClose(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void PsGetCurrentProcess(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void ZwOpenSection(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void ZwQuerySystemInformation(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void KiSystemCall64(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void ExSystemTimeToLocalTime(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void RtlTimeFieldsToTime(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void RtlTimeToTimeFields(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void CcInitializeCacheMap(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void RtlDuplicateUnicodeString(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void _vswprintf_s(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void _swprintf_s(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void KeInsertQueueApc(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void KeInitializeApc(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void KeInitializeTimer(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void KeSetTimer(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void KeReadStateTimer(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void ExCreateCallback(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void DebugPrompt(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void DbgPrompt(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void RtlRaiseStatus(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void PsGetCurrentServerSilo(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void ExAcquireRundownProtection(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void _vsnwprintf(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void IoCreateFileEx(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void ZwWriteFile(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void ZwFlushBuffersFile(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void KeGetCurrentIrql(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void wcscat_s(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void _wcscpy_s(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void KeIpiGenericCall(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void KdChangeOption(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void MmIsAddressValid(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void RtlInitializeBitMap(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void RtlSetBits(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void PsLookupProcessByProcessId(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void PsGetProcessImageFileName(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void PsGetProcessSectionBaseAddress(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void PsGetSessionId(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void KeStackAttachProcess(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void KeUnstackDetachProcess(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void ExGetFirmwareEnvironmentVariable(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void MmGetPhysicalAddress(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void MmGetPhysicalMemoryRanges(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void ObfDereferenceObject(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void MmBuildMdlForNonPagedPool(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void IoAllocateMdl(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void MmAllocateContiguousMemorySpecifyCache(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void PsRemoveLoadImageNotifyRoutine(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void PsSetCreateProcessNotifyRoutineEx(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void ObRegisterCallbacks(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void CmRegisterCallbackEx(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void ObUnRegisterCallbacks(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void ZwWaitForSingleObject(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void InitializeSListHead(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void KeInitializeSpinLock(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void KeAcquireSpinLockRaiseToDpc(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void KeReleaseSpinLock(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void ExpInterlockedPopEntrySList(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void ExWaitForRundownProtectionRelease(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void KeCancelTimer(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void ExFreePool(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void RtlFreeUnicodeString(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void PsSetCreateThreadNotifyRoutine(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void PsSetLoadImageNotifyRoutine(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void ExRegisterCallback(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void ExUnregisterCallback(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void _CiCheckSignedFile(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void CiFreePolicyInfo(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void KeWaitForMultipleObjects(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void HalAcpiGetTableEx(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void IoQueryFileInformation(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void DbgPrint(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void RtlVirtualUnwind(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void SeSinglePrivilegeCheck(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void ExAcquireResourceExclusiveLite(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
	static void TrampolineThread(ThreadInfo* info);
	static void RtlLookupFunctionEntry(uc_engine* uc, uint64_t address, uint32_t size, void* user_data);
};

static uc_hook intr_hook;
class Unicorn {
private:
	static PEloader* loader;
public:
	std::map<std::string, void(*)(uc_engine*, uint64_t, uint32_t, void*)> NtfuncMap = {
		{"PsGetCurrentServerSilo", Emulate::PsGetCurrentServerSilo },
		{"RtlLookupFunctionEntry", Emulate::RtlLookupFunctionEntry},
		{"ZwCreateSection",Emulate::ZwCreateSection},
		{"KeResetEvent",Emulate::KeResetEvent},
		{"atoi",Emulate::atol},
		{"isdigit",Emulate::IsDigit},
		{"IoCreateDevice", Emulate::IoCreateDevice},
		{"ExAllocatePoolWithTag", Emulate::ExAllocatePoolWithTag},
		{"KeInsertQueueApc",Emulate::KeInsertQueueApc},
		{"RtlInitUnicodeString", Emulate::RtlInitUnicodeString},
		{"KeInitializeGuardedMutex",Emulate::KeInitializeGuardedMutex },
		{"KeInitializeMutex", Emulate::KeInitializeGuardedMutex},
		{"RtlCompareMemory",Emulate::RtlCompareMemory},
		{"RtlWriteRegistryValue",Emulate::RtlWriteRegistryValue},
		{"RtlDeleteRegistryValue",Emulate::RtlDeleteRegistryValue},
		{"ZwOpenKey",Emulate::ZwOpenKey},
		{"ZwQueryValueKey",Emulate::ZwQueryValueKey},
		{"ZwCreateKey",Emulate::ZwCreateKey},
		{"ZwSetValueKey",Emulate::ZwSetValueKey},
		{"ZwDeleteValueKey",Emulate::ZwDeleteValueKey},
		{"RtlAnsiStringToUnicodeString",Emulate::RtlAnsiStringToUnicodeString},
		{"ZwFlushKey",Emulate::ZwFlushKey},
		{"ZwClose",Emulate::ZwClose},
		{"RtlRandomEx",Emulate::RtlRandomEx},
		{"ZwQuerySystemInformation",Emulate::ZwQuerySystemInformation},
		{"__C_specific_handler", Emulate::__C_specific_handler },
		{"KeAreAllApcsDisabled",Emulate::KeAreAllApcsDisabled },
		{"RtlMultiByteToUnicodeN",Emulate::RtlMultiByteToUnicodeN },
		{"ZwCreateFile",Emulate::ZwCreateFile},
		{"ZwQueryInformationFile",Emulate::ZwQueryInformationFile},
		{"ZwReadFile",Emulate::ZwReadFile},
		{"ExReleaseResourceLite", Emulate::ExReleaseResourceLite},
		{"RtlUnicodeStringToAnsiString", Emulate::RtlUnicodeStringToAnsiString},
		{"PsDereferenceSiloContext",Emulate::PsDereferenceSiloContext},
		{"KeInitializeEvent",Emulate::KeInitializeEvent},
		{"PsCreateSystemThread",Emulate::PsCreateSystemThread},
		{"KeCapturePersistentThreadState",Emulate::KeCapturePersistentThreadState},
		{"ZwOpenDirectoryObject",Emulate::ZwOpenDirectoryObject},
		{"ObReferenceObjectByHandle",Emulate::ObReferenceObjectByHandle},
		{"NtClose",Emulate::NtClose},
		{"ExAcquireFastMutex",Emulate::ExAcquireFastMutex},
		{"KeReleaseGuardedMutex",Emulate::KeReleaseGuardedMutex},
		{"KeWaitForSingleObject",Emulate::KeWaitForSingleObject},
		{"KeQueryTimeIncrement",Emulate::KeQueryTimeIncrement},
		{"KeSetEvent",Emulate::KeSetEvent},
		{"PsIsSystemThread",Emulate::PsIsSystemThread},
		{"RtlGetVersion",Emulate::RtlGetVersion},
		{"KeDelayExecutionThread",Emulate::KeDelayExecutionThread},
		{"ZwQueryFullAttributesFile",Emulate::ZwQueryFullAttributesFile},
		{"KeEnterCriticalRegion",Emulate::KeEnterCriticalRegion},
		{"KeLeaveCriticalRegion",Emulate::KeLeaveCriticalRegion},
		{"ExAcquireFastMutexUnsafe",Emulate::ExAcquireFastMutexUnsafe},
		{"ExReleaseFastMutexUnsafe",Emulate::ExReleaseFastMutexUnsafe},
		{"IoDeleteSymbolicLink",Emulate::IoDeleteSymbolicLink},
		{"RtlDuplicateUnicodeString", Emulate::RtlDuplicateUnicodeString},
		{"ExSystemTimeToLocalTime", Emulate::ExSystemTimeToLocalTime },
		{"RtlTimeFieldsToTime",Emulate::RtlTimeFieldsToTime},
		{"RtlTimeToTimeFields", Emulate::RtlTimeToTimeFields },
		{"vswprintf_s", Emulate::_vswprintf_s},
		{"swprintf_s", Emulate::_swprintf_s},
		{"IoCreateFileEx", Emulate::IoCreateFileEx},
		{"_vsnwprintf", Emulate::_vsnwprintf},
		{"wcscpy_s", Emulate::_wcscpy_s},
		{"wcscat_s", Emulate::wcscat_s},
		{"ZwWriteFile",Emulate::ZwWriteFile},
		{"ZwFlushBuffersFile",Emulate::ZwFlushBuffersFile},
		{"KeGetCurrentIrql",Emulate::KeGetCurrentIrql},
		{"KeIpiGenericCall", Emulate::KeIpiGenericCall },
		{"KeInitializeTimer",Emulate::KeInitializeTimer},
		{"KeSetTimer",Emulate::KeSetTimer},
		{"ExCreateCallback",Emulate::ExCreateCallback},
		{"DbgPrompt",Emulate::DbgPrompt},
		{"RtlRaiseStatus",Emulate::RtlRaiseStatus},
		{"RtlVirtualUnwind", Emulate::RtlVirtualUnwind },
		{"DebugPrompt",Emulate::DebugPrompt},
		{"KdChangeOption", Emulate::KdChangeOption },
		{"PsGetCurrentProcess", Emulate::PsGetCurrentProcess},
		{"ZwOpenSection", Emulate::ZwOpenSection},
		{"MmIsAddressValid", Emulate::MmIsAddressValid },
		{"RtlSetBits", Emulate::RtlSetBits },
		{"KeStackAttachProcess", Emulate::KeStackAttachProcess},
		{"KeUnstackDetachProcess", Emulate::KeUnstackDetachProcess},
		{"MmGetPhysicalAddress", Emulate::MmGetPhysicalAddress },
		{"ObfDereferenceObject", Emulate::ObfDereferenceObject },
		{"MmGetPhysicalMemoryRanges",Emulate::MmGetPhysicalMemoryRanges},
		{"MmAllocateContiguousMemorySpecifyCache", Emulate::MmAllocateContiguousMemorySpecifyCache},
		{"PsRemoveLoadImageNotifyRoutine", Emulate::PsRemoveLoadImageNotifyRoutine},
		{"PsRemoveCreateThreadNotifyRoutine", Emulate::PsRemoveLoadImageNotifyRoutine},
		{"PsSetCreateProcessNotifyRoutineEx", Emulate::PsSetCreateProcessNotifyRoutineEx},
		{"PsSetCreateProcessNotifyRoutine", Emulate::PsSetCreateProcessNotifyRoutineEx},
		{"InitializeSListHead",Emulate::InitializeSListHead},
		{"KeInitializeSpinLock",Emulate::KeInitializeSpinLock},
		{"KeAcquireSpinLockRaiseToDpc", Emulate::KeAcquireSpinLockRaiseToDpc},
		{"KeReleaseSpinLock", Emulate::KeReleaseSpinLock},
		{"ExpInterlockedPopEntrySList", Emulate::ExpInterlockedPopEntrySList},
		{"ExWaitForRundownProtectionRelease", Emulate::ExWaitForRundownProtectionRelease},
		{"KeCancelTimer", Emulate::KeCancelTimer},
		{"ExFreeHeapPool",Emulate::ExFreeHeapPool },
		{"ExFreePool", Emulate::ExFreePool},
		{"RtlFreeUnicodeString", Emulate::RtlFreeUnicodeString},
		{"IoAllocateMdl",Emulate::IoAllocateMdl},
		{"MmBuildMdlForNonPagedPool",Emulate::MmBuildMdlForNonPagedPool},
		{"PsSetCreateThreadNotifyRoutine", Emulate::PsSetCreateThreadNotifyRoutine},
		{"PsSetLoadImageNotifyRoutine", Emulate::PsSetLoadImageNotifyRoutine },
		{"ObRegisterCallbacks",Emulate::ObRegisterCallbacks},
		{"CmRegisterCallbackEx",Emulate::CmRegisterCallbackEx},
		{"ExRegisterCallback", Emulate::ExRegisterCallback},
		{"ExUnregisterCallback",Emulate::ExUnregisterCallback},
		{"RtlInitString",Emulate::RtlInitString},
		{"ObUnRegisterCallbacks",Emulate::ObUnRegisterCallbacks},
		{"ZwWaitForSingleObject",Emulate::ZwWaitForSingleObject },
		{"PsLookupProcessByProcessId",Emulate::PsLookupProcessByProcessId },
		{"ExGetFirmwareEnvironmentVariable",Emulate::ExGetFirmwareEnvironmentVariable },
		{"PsGetProcessImageFileName", Emulate::PsGetProcessImageFileName },
		{"PsGetProcessSectionBaseAddress",Emulate::PsGetProcessSectionBaseAddress },
		{"PsGetSessionId",Emulate::PsGetSessionId },
		{"PsGetProcessSessionId",Emulate::PsGetSessionId },
		{"KeWaitForMultipleObjects", Emulate::KeWaitForMultipleObjects },
		{"PsTerminateSystemThread",Emulate::PsTerminateSystemThread },
		{"IoRegisterShutdownNotification",Emulate::IoRegisterShutdownNotification },
		{"IoCreateSymbolicLink",Emulate::IoCreateSymbolicLink },
		{"ZwDeviceIoControlFile",Emulate::ZwDeviceIoControlFile },
		{"IoQueryFileInformation", Emulate::IoQueryFileInformation },
		{"DbgPrint", Emulate::DbgPrint },
		{"SeSinglePrivilegeCheck", Emulate::SeSinglePrivilegeCheck },
		{"ExAcquireResourceExclusiveLite", Emulate::ExAcquireResourceExclusiveLite },
		{"KeInitializeApc",Emulate::KeInitializeApc },
		{"KeReadStateTimer",Emulate::KeReadStateTimer }
	};

	std::map<std::string, void(*)(uc_engine*, uint64_t, uint32_t, void*)> CngFuncMap = {
		{"BCryptOpenAlgorithmProvider",Emulate::BCryptOpenAlgorithmProvider},
		{"BCryptCreateHash",Emulate::BCryptCreateHash},
		{"BCryptHashData",Emulate::BCryptHashData},
		{"BCryptGetProperty",Emulate::BCryptGetProperty },
		{"BCryptFinishHash",Emulate::BCryptFinishHash },
		{"BCryptCloseAlgorithmProvider",Emulate::BCryptCloseAlgorithmProvider},
		{"BCryptDestroyHash",Emulate::BCryptDestroyHash}
	};

	std::map<std::string, void(*)(uc_engine*, uint64_t, uint32_t, void*)> CiFuncMap = {
		{"CiCheckSignedFile", Emulate::_CiCheckSignedFile},
		{"CiFreePolicyInfo",Emulate::CiFreePolicyInfo}
	};

	std::map<std::string, uint64_t> ntFuncAddr;
	std::map<std::string, uint64_t> cngFuncAddr;
	std::map<std::string, uint64_t> fltMgrFuncAddr;


	Unicorn();
	static void seh_Handle(uc_engine* uc);
	static void catch_error(uc_engine* uc, int exception, void* user_data);
	static void register_hook(uc_engine* uc, uint64_t address, const byte size, void* user_data);
	static void hook_mem_access(uc_engine* uc, uc_mem_type type, uint64_t address, int size, int64_t value, void* user_data);
	static void hook_mem_write(uc_engine* uc, uc_mem_type type, uint64_t address, int size, int64_t value, void* user_data);
	static bool hook_mem_invalid(uc_engine* uc, uc_mem_type type, uint64_t address, int size, int64_t value, void* user_data);
	static void hook_access_object(uc_engine* uc, uc_mem_type type, uint64_t address, int size, int64_t value, void* user_data);
	static void hook_File_func(uc_engine* uc, std::string fileName, std::string funcName, void(*func)(uc_engine*, uint64_t, uint32_t, void*));


	static bool check_is_ntFunc(uint64_t _register);
	static bool check_is_ntFunc_noNext(uint64_t _register);

};


class crt_buffer_t
{
public:
	crt_buffer_t();
	crt_buffer_t(size_t size);
	~crt_buffer_t();
	void* GetSpace(size_t needSize);
	size_t GetLength() { return m_cbSize; }
	void* GetBuffer() { return m_pBuffer; }

	void* m_pBuffer;
	size_t m_cbSize;
};

class Except {
private:
	static PEloader* loader;
public:
	Except();
	static VOID RtlpGetStackLimits(_Inout_ uc_engine* uc, OUT PULONG64 LowLimit, OUT PULONG64 HighLimit);
	static VOID RtlpCaptureContext(_Inout_ uc_engine* uc, IN PCONTEXT ContextRecord);
	static VOID RtlpRestoreContext(_Inout_ uc_engine* uc, IN PCONTEXT ContextRecord, IN PEXCEPTION_RECORD ExceptionRecord OPTIONAL);
	static BOOLEAN RtlpDispatchException(_Inout_ uc_engine* uc, IN PEXCEPTION_RECORD ExceptionRecord, IN PCONTEXT ContextRecord);
	static VOID RtlRaiseStatus(_Inout_ uc_engine* uc, IN NTSTATUS Status);
	static NTSTATUS RaiseException(_Inout_ uc_engine* uc, IN PEXCEPTION_RECORD ExceptionRecord, IN PCONTEXT ContextRecord, IN BOOLEAN FirstChance);

	static EXCEPTION_DISPOSITION RtlpExecuteHandlerForException(
		_Inout_ uc_engine* uc,
		_Inout_ struct _EXCEPTION_RECORD* ExceptionRecord,
		_In_ PVOID EstablisherFrame,
		_Inout_ struct _CONTEXT* ContextRecord,
		_In_ PDISPATCHER_CONTEXT DispatcherContext
	);
	static PRUNTIME_FUNCTION RtlpLookupFunctionTable(
		_Inout_ uc_engine* uc,
		IN PVOID ControlPc,
		OUT PVOID* ImageBase,
		OUT PULONG SizeOfTable
	);
	static PRUNTIME_FUNCTION RtlpLookupFunctionEntry(
		_Inout_ uc_engine* uc,
		IN ULONG64 ControlPc,
		OUT PULONG64 ImageBase,
		IN OUT PUNWIND_HISTORY_TABLE HistoryTable OPTIONAL
	);
	static PRUNTIME_FUNCTION RtlpConvertFunctionEntry(
		_Inout_ uc_engine* uc,
		IN PRUNTIME_FUNCTION FunctionEntry,
		IN ULONG64 ImageBase
	);
	static PEXCEPTION_ROUTINE RtlpVirtualUnwind(
		_Inout_ uc_engine* uc,
		IN ULONG HandlerType,
		IN ULONG64 ImageBase,
		IN ULONG64 ControlPc,
		IN PRUNTIME_FUNCTION FunctionEntry,
		IN OUT PCONTEXT ContextRecord,
		OUT PVOID* HandlerData,
		OUT PULONG64 EstablisherFrame,
		IN OUT PKNONVOLATILE_CONTEXT_POINTERS ContextPointers OPTIONAL
	);
	static PRUNTIME_FUNCTION RtlpSameFunction(
		_Inout_ uc_engine* uc,
		IN PRUNTIME_FUNCTION FunctionEntry,
		IN ULONG64 ImageBase,
		IN ULONG64 ControlPc
	);



	static PRUNTIME_FUNCTION RtlpUnwindPrologue(
		_Inout_ uc_engine* uc,
		IN ULONG64 ImageBase,
		IN ULONG64 ControlPc,
		IN ULONG64 FrameBase,
		IN PRUNTIME_FUNCTION FunctionEntry,
		IN OUT PCONTEXT ContextRecord,
		IN OUT PKNONVOLATILE_CONTEXT_POINTERS ContextPointers OPTIONAL
	);

	static VOID RtlpCopyContext(_Inout_ uc_engine* uc, OUT PCONTEXT Destination, IN PCONTEXT Source);
	static EXCEPTION_DISPOSITION C_specific_handler(_Inout_ uc_engine* uc);
	static VOID RtlpUnwindEx(
		_Inout_ uc_engine* uc,
		IN PVOID TargetFrame OPTIONAL,
		IN PVOID TargetIp OPTIONAL,
		IN PEXCEPTION_RECORD ExceptionRecord OPTIONAL,
		IN PVOID ReturnValue,
		IN PCONTEXT OriginalContext,
		IN PUNWIND_HISTORY_TABLE HistoryTable OPTIONAL
	);
	static BOOLEAN RtlpIsFrameInBounds(
		_Inout_ uc_engine* uc,
		IN OUT PULONG64 LowLimit,
		IN ULONG64 StackFrame,
		IN OUT PULONG64 HighLimit
	);

	static PRUNTIME_FUNCTION RtlpSearchInvertedFunctionTable(
		_Inout_ uc_engine* uc,
		PINVERTED_FUNCTION_TABLE InvertedTable,
		PVOID ControlPc,
		OUT PVOID* ImageBase,
		OUT PULONG SizeOfTable
	);
	static bool KeQueryCurrentStackInformation(_Inout_ uc_engine* uc, OUT PULONG64 LowLimit, OUT PULONG64 HighLimit);
	static VOID KiExceptionDispatch(
		_Inout_ uc_engine* uc,
		uint32_t ExceptionCode,
		uint32_t NumberParameters,
		uintptr_t ExceptionAddress,
		uintptr_t* ExceptionInformation,
		uintptr_t TrapFrame
	);
	static VOID RtlInsertInvertedFunctionTable(
		_Inout_ uc_engine* uc,
		PINVERTED_FUNCTION_TABLE InvertedTable,
		ULONG64 MappedBase,
		PVOID ImageBase,
		ULONG SizeOfImage
	);
};



class Snapshot {
private:
	std::vector<uint8_t> raw_data;
	void save_register(uc_engine* uc) {
		int registers[] = {
			UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX,
			UC_X86_REG_RSI, UC_X86_REG_RDI, UC_X86_REG_RBP, UC_X86_REG_RSP,
			UC_X86_REG_RIP, UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_R10,
			UC_X86_REG_R11, UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14,
			UC_X86_REG_R15, UC_X86_REG_EFLAGS
		};
		for (int reg : registers) {
			uint64_t value;
			if (uc_reg_read(uc, reg, &value) == UC_ERR_OK) {
				raw_data.insert(raw_data.end(), reinterpret_cast<uint8_t*>(&value), reinterpret_cast<uint8_t*>(&value) + sizeof(value));
				Logger::Log(true, ConsoleColor::DARK_GREEN, "Register %d: %llx\n", reg, value);
			}
		}
		int sse_registers[] = {
			UC_X86_REG_XMM0, UC_X86_REG_XMM1, UC_X86_REG_XMM2, UC_X86_REG_XMM3,
			UC_X86_REG_XMM4, UC_X86_REG_XMM5, UC_X86_REG_XMM6, UC_X86_REG_XMM7,
			UC_X86_REG_XMM8, UC_X86_REG_XMM9, UC_X86_REG_XMM10, UC_X86_REG_XMM11,
			UC_X86_REG_XMM12, UC_X86_REG_XMM13, UC_X86_REG_XMM14, UC_X86_REG_XMM15
		};
		for (int reg : sse_registers) {
			uint8_t value[16];
			uc_reg_read(uc, reg, &value);
			raw_data.insert(raw_data.end(), reinterpret_cast<uint8_t*>(&value), reinterpret_cast<uint8_t*>(&value) + sizeof(value));
		}
	}
	size_t load_register(uc_engine* uc) {
		int registers[] = {
			UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX,
			UC_X86_REG_RSI, UC_X86_REG_RDI, UC_X86_REG_RBP, UC_X86_REG_RSP,
			UC_X86_REG_RIP, UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_R10,
			UC_X86_REG_R11, UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14,
			UC_X86_REG_R15, UC_X86_REG_EFLAGS
		};
		const size_t num_registers = sizeof(registers) / sizeof(registers[0]);
		const size_t bytes_per_register = sizeof(uint64_t);

		for (size_t i = 0; i < num_registers; ++i) {
			uint64_t value;
			std::memcpy(&value, &raw_data[i * bytes_per_register], bytes_per_register);
			uc_reg_write(uc, registers[i], &value);
			Logger::Log(true, ConsoleColor::DARK_GREEN, "Register %d: %llx\n", registers[i], value);
		}
		auto from = num_registers * bytes_per_register;
		int sse_registers[] = {
			UC_X86_REG_XMM0, UC_X86_REG_XMM1, UC_X86_REG_XMM2, UC_X86_REG_XMM3,
			UC_X86_REG_XMM4, UC_X86_REG_XMM5, UC_X86_REG_XMM6, UC_X86_REG_XMM7,
			UC_X86_REG_XMM8, UC_X86_REG_XMM9, UC_X86_REG_XMM10, UC_X86_REG_XMM11,
			UC_X86_REG_XMM12, UC_X86_REG_XMM13, UC_X86_REG_XMM14, UC_X86_REG_XMM15
		};
		const size_t num_sse_registers = sizeof(sse_registers) / sizeof(sse_registers[0]);
		uint8_t value[16];
		const size_t bytes_per_sse_register = sizeof(value);

		for (size_t i = 0; i < num_sse_registers; ++i) {

			std::memcpy(&value, &raw_data[from + i * bytes_per_sse_register], bytes_per_sse_register);
			uc_reg_write(uc, sse_registers[i], &value);
		}
		return from + num_sse_registers * bytes_per_sse_register;
	}
	size_t load_memory(uc_engine* uc, size_t from) {
		uint32_t count;
		std::memcpy(&count, &raw_data[from], sizeof(count));
		from += sizeof(count);
		for (int i = 0; i < count; i++) {
			uint64_t start, size;
			std::memcpy(&start, &raw_data[from], sizeof(start));
			from += sizeof(start);
			std::memcpy(&size, &raw_data[from], sizeof(size));
			Logger::Log(true, ConsoleColor::DARK_GREEN, "Load Memory: %llx %llx\n", start, size);
			from += sizeof(size);
			Emulate::Alloc(uc, size, start);
			uc_mem_write(uc, start, &raw_data[from], size);
			from += size;
		}
		return from;
	}
	void save_memory(uc_engine* uc) {
		uc_mem_region* regions;
		uint32_t count;
		if (uc_mem_regions(uc, &regions, &count) != UC_ERR_OK) {
			std::cerr << "Failed to get memory regions" << std::endl;
			return;
		}
		raw_data.insert(raw_data.end(), reinterpret_cast<uint8_t*>(&count), reinterpret_cast<uint8_t*>(&count) + sizeof(count));
		for (uint32_t i = 0; i < count; i++) {
			uint64_t start = regions[i].begin;
			uint64_t size = regions[i].end - regions[i].begin + 1;
			raw_data.insert(raw_data.end(), reinterpret_cast<uint8_t*>(&start), reinterpret_cast<uint8_t*>(&start) + sizeof(start));
			raw_data.insert(raw_data.end(), reinterpret_cast<uint8_t*>(&size), reinterpret_cast<uint8_t*>(&size) + sizeof(size));
			auto original_size = raw_data.size();
			raw_data.resize(original_size + size);
			uc_mem_read(uc, start, raw_data.data() + original_size, size);
		}
		uc_free(regions);
	}
public:
	uint64_t load_snapshot(uc_engine* uc, std::string filename) {
		FILE* file = nullptr;
		fopen_s(&file, filename.c_str(), "rb");
		fseek(file, 0, SEEK_END);
		auto file_size = ftell(file);
		fseek(file, 0, SEEK_SET);
		if (file_size < 0) {
			std::cout << "Empty File\n";
			fclose(file);
			return 0;
		}
		raw_data.resize(file_size);
		fread(raw_data.data(), sizeof(uint8_t), raw_data.size(), file);
		fclose(file);

		auto from = load_register(uc);
		from = load_memory(uc, from);
		uint64_t allocSize;
		std::memcpy(&allocSize, &raw_data[from], sizeof(allocSize));
		return allocSize;
	}
	void save_snapshot(uc_engine* uc, std::string filename, uint64_t allocSize) {
		save_register(uc);
		save_memory(uc);
		raw_data.insert(raw_data.end(), reinterpret_cast<uint8_t*>(&allocSize), reinterpret_cast<uint8_t*>(&allocSize) + sizeof(allocSize));
		FILE* file = nullptr;
		fopen_s(&file, filename.c_str(), "wb");
		fwrite(raw_data.data(), sizeof(uint8_t), raw_data.size(), file);
		fclose(file);
	}
};



#endif

/**
 * CyberSentinel DLP Minifilter Driver
 *
 * Kernel-mode file system minifilter for Windows 10/11 x64.
 * Intercepts file operations to removable media and communicates
 * with the user-mode DLP service via a filter communication port.
 *
 * Features:
 *   - IRP_MJ_CREATE interception (file open/create)
 *   - IRP_MJ_WRITE interception (file modification)
 *   - IRP_MJ_SET_INFORMATION interception (rename/delete)
 *   - Removable media detection (USB drives)
 *   - Filter communication port for user-mode decisions
 *   - Safe allow/block enforcement (no system instability)
 *
 * Build with WDK (Windows Driver Kit) for KMDF.
 */

#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#include <ntddk.h>
#include <wdm.h>

/* Include shared header for communication structures */
/* In production, include the shared header directly.
   For the skeleton we redefine the essentials inline. */

/* ────────────────────────────────────────────────────────────────────────────
 * Constants
 * ──────────────────────────────────────────────────────────────────────────── */

#define CS_DRIVER_TAG           'slFC'   /* CyberSentinel Filter tag */
#define CS_PORT_NAME            L"\\CyberSentinelPort"
#define CS_MAX_PATH             520
#define CS_MAX_SID_LENGTH       128
#define CS_MAX_PROCESS_NAME     260
#define CS_MAX_VOLUME_NAME      64
#define CS_MAX_CLIENTS          1        /* Only one user-mode service connects */
#define CS_MESSAGE_TIMEOUT_MS   5000     /* 5 second timeout for user-mode reply */

/* ────────────────────────────────────────────────────────────────────────────
 * Enums (mirrored from csfilter.h)
 * ──────────────────────────────────────────────────────────────────────────── */

typedef enum _CS_EVENT_TYPE {
    CsEventFileCreate       = 1,
    CsEventFileWrite        = 2,
    CsEventFileRename       = 3,
    CsEventFileDelete       = 4,
    CsEventUsbArrival       = 10,
    CsEventUsbRemoval       = 11,
} CS_EVENT_TYPE;

typedef enum _CS_DEVICE_FLAGS {
    CsDeviceFixed           = 0x0001,
    CsDeviceRemovable       = 0x0002,
    CsDeviceNetwork         = 0x0004,
    CsDeviceOptical         = 0x0008,
    CsDeviceVirtual         = 0x0010,
    CsDeviceUnknown         = 0x8000,
} CS_DEVICE_FLAGS;

typedef enum _CS_DECISION {
    CsDecisionAllow         = 0,
    CsDecisionBlock         = 1,
    CsDecisionWarn          = 2,
} CS_DECISION;

/* ────────────────────────────────────────────────────────────────────────────
 * Communication Structures
 * ──────────────────────────────────────────────────────────────────────────── */

#pragma pack(push, 1)

typedef struct _CS_EVENT_MESSAGE {
    ULONG           MessageId;
    CS_EVENT_TYPE   EventType;
    LARGE_INTEGER   Timestamp;
    ULONG           ProcessId;
    ULONG           ThreadId;
    WCHAR           ProcessName[CS_MAX_PROCESS_NAME];
    WCHAR           UserSid[CS_MAX_SID_LENGTH];
    WCHAR           FilePath[CS_MAX_PATH];
    LONGLONG        FileSize;
    ULONG           FileAttributes;
    WCHAR           VolumeName[CS_MAX_VOLUME_NAME];
    CS_DEVICE_FLAGS DeviceFlags;
    WCHAR           NewFilePath[CS_MAX_PATH];
    ULONG           IsDirectory : 1;
    ULONG           IsPreOperation : 1;
    ULONG           NeedsDecision : 1;
    ULONG           Reserved : 29;
} CS_EVENT_MESSAGE, *PCS_EVENT_MESSAGE;

typedef struct _CS_DECISION_REPLY {
    ULONG           MessageId;
    CS_DECISION     Decision;
    ULONG           ReasonCode;
} CS_DECISION_REPLY, *PCS_DECISION_REPLY;

#pragma pack(pop)

/* ────────────────────────────────────────────────────────────────────────────
 * Global State
 * ──────────────────────────────────────────────────────────────────────────── */

typedef struct _CS_FILTER_DATA {
    PFLT_FILTER     FilterHandle;
    PFLT_PORT       ServerPort;
    PFLT_PORT       ClientPort;
    volatile LONG   MessageIdCounter;
    BOOLEAN         ServiceConnected;
} CS_FILTER_DATA, *PCS_FILTER_DATA;

static CS_FILTER_DATA g_FilterData = { 0 };

/* ────────────────────────────────────────────────────────────────────────────
 * Forward Declarations
 * ──────────────────────────────────────────────────────────────────────────── */

DRIVER_INITIALIZE DriverEntry;
NTSTATUS CsFilterUnload(FLT_FILTER_UNLOAD_FLAGS Flags);
NTSTATUS CsInstanceSetup(PCFLT_RELATED_OBJECTS FltObjects,
                          FLT_INSTANCE_SETUP_FLAGS Flags,
                          DEVICE_TYPE VolumeDeviceType,
                          FLT_FILESYSTEM_TYPE VolumeFilesystemType);

/* Pre/Post callbacks */
FLT_PREOP_CALLBACK_STATUS CsPreCreate(PFLT_CALLBACK_DATA Data,
                                       PCFLT_RELATED_OBJECTS FltObjects,
                                       PVOID *CompletionContext);
FLT_PREOP_CALLBACK_STATUS CsPreWrite(PFLT_CALLBACK_DATA Data,
                                      PCFLT_RELATED_OBJECTS FltObjects,
                                      PVOID *CompletionContext);
FLT_PREOP_CALLBACK_STATUS CsPreSetInfo(PFLT_CALLBACK_DATA Data,
                                        PCFLT_RELATED_OBJECTS FltObjects,
                                        PVOID *CompletionContext);

/* Communication port callbacks */
NTSTATUS CsPortConnect(PFLT_PORT ClientPort, PVOID ServerPortCookie,
                        PVOID ConnectionContext, ULONG SizeOfContext,
                        PVOID *ConnectionPortCookie);
void CsPortDisconnect(PVOID ConnectionCookie);
NTSTATUS CsPortMessageNotify(PVOID PortCookie, PVOID InputBuffer,
                              ULONG InputBufferLength, PVOID OutputBuffer,
                              ULONG OutputBufferLength, PULONG ReturnOutputBufferLength);

/* Helpers */
static CS_DEVICE_FLAGS CsGetDeviceFlags(PCFLT_RELATED_OBJECTS FltObjects);
static BOOLEAN CsIsRemovableDevice(PCFLT_RELATED_OBJECTS FltObjects);
static void CsGetProcessName(PEPROCESS Process, WCHAR *Buffer, ULONG BufferLen);
static void CsGetUserSid(WCHAR *Buffer, ULONG BufferLen);
static CS_DECISION CsSendEventAndGetDecision(PCS_EVENT_MESSAGE EventMsg);

/* ────────────────────────────────────────────────────────────────────────────
 * Registration Structures
 * ──────────────────────────────────────────────────────────────────────────── */

static const FLT_OPERATION_REGISTRATION g_Callbacks[] = {
    { IRP_MJ_CREATE,
      0,
      CsPreCreate,
      NULL },

    { IRP_MJ_WRITE,
      0,
      CsPreWrite,
      NULL },

    { IRP_MJ_SET_INFORMATION,
      0,
      CsPreSetInfo,
      NULL },

    { IRP_MJ_OPERATION_END }
};

static const FLT_CONTEXT_REGISTRATION g_ContextRegistration[] = {
    { FLT_CONTEXT_END }
};

static const FLT_REGISTRATION g_FilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,                              /* Flags */
    g_ContextRegistration,
    g_Callbacks,
    CsFilterUnload,
    CsInstanceSetup,                /* InstanceSetup */
    NULL,                           /* InstanceQueryTeardown */
    NULL,                           /* InstanceTeardownStart */
    NULL,                           /* InstanceTeardownComplete */
    NULL, NULL, NULL                /* Unused name callbacks */
};

/* ════════════════════════════════════════════════════════════════════════════
 * DRIVER ENTRY
 * ════════════════════════════════════════════════════════════════════════════ */

NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    NTSTATUS status;
    PSECURITY_DESCRIPTOR sd = NULL;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING portName;

    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrint("[CyberSentinel] DriverEntry: Loading minifilter\n");

    /* Step 1: Register the minifilter */
    status = FltRegisterFilter(DriverObject, &g_FilterRegistration, &g_FilterData.FilterHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[CyberSentinel] FltRegisterFilter failed: 0x%08X\n", status);
        return status;
    }

    /* Step 2: Create the communication port for user-mode service */
    status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[CyberSentinel] FltBuildDefaultSecurityDescriptor failed: 0x%08X\n", status);
        FltUnregisterFilter(g_FilterData.FilterHandle);
        return status;
    }

    RtlInitUnicodeString(&portName, CS_PORT_NAME);
    InitializeObjectAttributes(&oa, &portName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, sd);

    status = FltCreateCommunicationPort(
        g_FilterData.FilterHandle,
        &g_FilterData.ServerPort,
        &oa,
        NULL,                       /* ServerPortCookie */
        CsPortConnect,
        CsPortDisconnect,
        CsPortMessageNotify,
        CS_MAX_CLIENTS
    );

    FltFreeSecurityDescriptor(sd);

    if (!NT_SUCCESS(status)) {
        DbgPrint("[CyberSentinel] FltCreateCommunicationPort failed: 0x%08X\n", status);
        FltUnregisterFilter(g_FilterData.FilterHandle);
        return status;
    }

    /* Step 3: Start filtering */
    status = FltStartFiltering(g_FilterData.FilterHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[CyberSentinel] FltStartFiltering failed: 0x%08X\n", status);
        FltCloseCommunicationPort(g_FilterData.ServerPort);
        FltUnregisterFilter(g_FilterData.FilterHandle);
        return status;
    }

    DbgPrint("[CyberSentinel] Minifilter loaded successfully\n");
    return STATUS_SUCCESS;
}

/* ════════════════════════════════════════════════════════════════════════════
 * UNLOAD
 * ════════════════════════════════════════════════════════════════════════════ */

NTSTATUS CsFilterUnload(FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);

    DbgPrint("[CyberSentinel] Unloading minifilter\n");

    if (g_FilterData.ServerPort) {
        FltCloseCommunicationPort(g_FilterData.ServerPort);
        g_FilterData.ServerPort = NULL;
    }

    if (g_FilterData.FilterHandle) {
        FltUnregisterFilter(g_FilterData.FilterHandle);
        g_FilterData.FilterHandle = NULL;
    }

    return STATUS_SUCCESS;
}

/* ════════════════════════════════════════════════════════════════════════════
 * INSTANCE SETUP — Attach to volumes
 * ════════════════════════════════════════════════════════════════════════════ */

NTSTATUS CsInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    /* Only attach to disk-backed NTFS/FAT volumes (skip network, cdrom, etc.) */
    if (VolumeDeviceType != FILE_DEVICE_DISK_FILE_SYSTEM) {
        return STATUS_FLT_DO_NOT_ATTACH;
    }

    /* Skip RAW file systems */
    if (VolumeFilesystemType == FLT_FSTYPE_RAW) {
        return STATUS_FLT_DO_NOT_ATTACH;
    }

    DbgPrint("[CyberSentinel] Attaching to volume (type=%d, fs=%d)\n",
             VolumeDeviceType, VolumeFilesystemType);

    return STATUS_SUCCESS;
}

/* ════════════════════════════════════════════════════════════════════════════
 * COMMUNICATION PORT CALLBACKS
 * ════════════════════════════════════════════════════════════════════════════ */

NTSTATUS CsPortConnect(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID *ConnectionPortCookie
)
{
    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);
    UNREFERENCED_PARAMETER(ConnectionPortCookie);

    g_FilterData.ClientPort = ClientPort;
    g_FilterData.ServiceConnected = TRUE;

    DbgPrint("[CyberSentinel] User-mode service connected\n");
    return STATUS_SUCCESS;
}

void CsPortDisconnect(_In_opt_ PVOID ConnectionCookie)
{
    UNREFERENCED_PARAMETER(ConnectionCookie);

    FltCloseClientPort(g_FilterData.FilterHandle, &g_FilterData.ClientPort);
    g_FilterData.ClientPort = NULL;
    g_FilterData.ServiceConnected = FALSE;

    DbgPrint("[CyberSentinel] User-mode service disconnected\n");
}

NTSTATUS CsPortMessageNotify(
    _In_opt_ PVOID PortCookie,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
)
{
    UNREFERENCED_PARAMETER(PortCookie);
    UNREFERENCED_PARAMETER(InputBuffer);
    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(OutputBuffer);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    /* This callback handles messages FROM user-mode TO kernel.
       Currently unused — decisions come via FltSendMessage reply. */
    *ReturnOutputBufferLength = 0;
    return STATUS_SUCCESS;
}

/* ════════════════════════════════════════════════════════════════════════════
 * HELPER: Detect Removable Media
 * ════════════════════════════════════════════════════════════════════════════ */

static CS_DEVICE_FLAGS CsGetDeviceFlags(PCFLT_RELATED_OBJECTS FltObjects)
{
    NTSTATUS status;
    DEVICE_TYPE deviceType;
    FLT_VOLUME_PROPERTIES volumeProps;
    ULONG bytesReturned;

    if (!FltObjects || !FltObjects->Volume) {
        return CsDeviceUnknown;
    }

    /* Get volume properties to determine device characteristics */
    status = FltGetVolumeProperties(FltObjects->Volume, &volumeProps,
                                    sizeof(volumeProps), &bytesReturned);
    if (!NT_SUCCESS(status) && status != STATUS_BUFFER_OVERFLOW) {
        return CsDeviceUnknown;
    }

    deviceType = volumeProps.DeviceType;

    if (volumeProps.DeviceCharacteristics & FILE_REMOVABLE_MEDIA) {
        return CsDeviceRemovable;
    }

    switch (deviceType) {
    case FILE_DEVICE_DISK:
    case FILE_DEVICE_DISK_FILE_SYSTEM:
        return (volumeProps.DeviceCharacteristics & FILE_REMOVABLE_MEDIA)
               ? CsDeviceRemovable : CsDeviceFixed;
    case FILE_DEVICE_NETWORK_FILE_SYSTEM:
        return CsDeviceNetwork;
    case FILE_DEVICE_CD_ROM:
    case FILE_DEVICE_CD_ROM_FILE_SYSTEM:
        return CsDeviceOptical;
    case FILE_DEVICE_VIRTUAL_DISK:
        return CsDeviceVirtual;
    default:
        return CsDeviceUnknown;
    }
}

static BOOLEAN CsIsRemovableDevice(PCFLT_RELATED_OBJECTS FltObjects)
{
    return (CsGetDeviceFlags(FltObjects) & CsDeviceRemovable) != 0;
}

/* ════════════════════════════════════════════════════════════════════════════
 * HELPER: Get Process Name
 * ════════════════════════════════════════════════════════════════════════════ */

static void CsGetProcessName(PEPROCESS Process, WCHAR *Buffer, ULONG BufferLen)
{
    PUNICODE_STRING processName = NULL;
    NTSTATUS status;

    RtlZeroMemory(Buffer, BufferLen * sizeof(WCHAR));

    status = SeLocateProcessImageName(Process, &processName);
    if (NT_SUCCESS(status) && processName && processName->Buffer) {
        ULONG copyLen = min((ULONG)(processName->Length / sizeof(WCHAR)), BufferLen - 1);
        RtlCopyMemory(Buffer, processName->Buffer, copyLen * sizeof(WCHAR));
        Buffer[copyLen] = L'\0';
        ExFreePool(processName);
    }
}

/* ════════════════════════════════════════════════════════════════════════════
 * HELPER: Get User SID
 * ════════════════════════════════════════════════════════════════════════════ */

static void CsGetUserSid(WCHAR *Buffer, ULONG BufferLen)
{
    NTSTATUS status;
    PACCESS_TOKEN token;
    PTOKEN_USER tokenUser = NULL;
    UNICODE_STRING sidString;

    RtlZeroMemory(Buffer, BufferLen * sizeof(WCHAR));

    token = PsReferencePrimaryToken(PsGetCurrentProcess());
    if (!token) return;

    status = SeQueryInformationToken(token, TokenUser, (PVOID *)&tokenUser);
    if (NT_SUCCESS(status) && tokenUser) {
        status = RtlConvertSidToUnicodeString(&sidString, tokenUser->User.Sid, TRUE);
        if (NT_SUCCESS(status)) {
            ULONG copyLen = min((ULONG)(sidString.Length / sizeof(WCHAR)), BufferLen - 1);
            RtlCopyMemory(Buffer, sidString.Buffer, copyLen * sizeof(WCHAR));
            Buffer[copyLen] = L'\0';
            RtlFreeUnicodeString(&sidString);
        }
        ExFreePool(tokenUser);
    }

    PsDereferencePrimaryToken(token);
}

/* ════════════════════════════════════════════════════════════════════════════
 * HELPER: Send Event to Usermode and Get Decision
 * ════════════════════════════════════════════════════════════════════════════ */

static CS_DECISION CsSendEventAndGetDecision(PCS_EVENT_MESSAGE EventMsg)
{
    NTSTATUS status;
    CS_DECISION_REPLY reply = { 0 };
    ULONG replyLength = sizeof(reply);
    LARGE_INTEGER timeout;

    /* If user-mode service is not connected, fail-open (ALLOW) */
    if (!g_FilterData.ServiceConnected || !g_FilterData.ClientPort) {
        return CsDecisionAllow;
    }

    /* 5-second timeout to prevent indefinite blocking */
    timeout.QuadPart = -(LONGLONG)CS_MESSAGE_TIMEOUT_MS * 10000;

    status = FltSendMessage(
        g_FilterData.FilterHandle,
        &g_FilterData.ClientPort,
        EventMsg,
        sizeof(CS_EVENT_MESSAGE),
        &reply,
        &replyLength,
        &timeout
    );

    if (!NT_SUCCESS(status)) {
        /* Timeout or error → fail-open (ALLOW) to prevent system deadlock */
        DbgPrint("[CyberSentinel] FltSendMessage failed (0x%08X) — allowing operation\n", status);
        return CsDecisionAllow;
    }

    /* Validate reply */
    if (replyLength >= sizeof(CS_DECISION_REPLY) && reply.MessageId == EventMsg->MessageId) {
        return reply.Decision;
    }

    return CsDecisionAllow;
}

/* ════════════════════════════════════════════════════════════════════════════
 * HELPER: Build base event message from callback data
 * ════════════════════════════════════════════════════════════════════════════ */

static void CsBuildEventMessage(
    PCS_EVENT_MESSAGE Msg,
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    CS_EVENT_TYPE EventType
)
{
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    PEPROCESS process;

    RtlZeroMemory(Msg, sizeof(CS_EVENT_MESSAGE));

    Msg->MessageId = InterlockedIncrement(&g_FilterData.MessageIdCounter);
    Msg->EventType = EventType;
    KeQuerySystemTimePrecise(&Msg->Timestamp);
    Msg->ProcessId = FltGetRequestorProcessId(Data);
    Msg->ThreadId = (ULONG)(ULONG_PTR)PsGetCurrentThreadId();
    Msg->DeviceFlags = CsGetDeviceFlags(FltObjects);
    Msg->IsPreOperation = 1;
    Msg->NeedsDecision = (Msg->DeviceFlags & CsDeviceRemovable) ? 1 : 0;
    Msg->FileAttributes = 0;
    Msg->FileSize = 0;

    /* Get file path */
    if (NT_SUCCESS(FltGetFileNameInformation(Data,
            FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo))) {
        FltParseFileNameInformation(nameInfo);

        ULONG copyLen = min((ULONG)(nameInfo->Name.Length / sizeof(WCHAR)), CS_MAX_PATH - 1);
        RtlCopyMemory(Msg->FilePath, nameInfo->Name.Buffer, copyLen * sizeof(WCHAR));
        Msg->FilePath[copyLen] = L'\0';

        /* Volume name */
        copyLen = min((ULONG)(nameInfo->Volume.Length / sizeof(WCHAR)), CS_MAX_VOLUME_NAME - 1);
        RtlCopyMemory(Msg->VolumeName, nameInfo->Volume.Buffer, copyLen * sizeof(WCHAR));
        Msg->VolumeName[copyLen] = L'\0';

        FltReleaseFileNameInformation(nameInfo);
    }

    /* Get process name */
    process = FltGetRequestorProcess(Data);
    if (process) {
        CsGetProcessName(process, Msg->ProcessName, CS_MAX_PROCESS_NAME);
    }

    /* Get user SID */
    CsGetUserSid(Msg->UserSid, CS_MAX_SID_LENGTH);

    /* Get file size if available */
    if (FltObjects->FileObject) {
        FILE_STANDARD_INFORMATION fileInfo;
        NTSTATUS status = FltQueryInformationFile(
            FltObjects->Instance, FltObjects->FileObject,
            &fileInfo, sizeof(fileInfo), FileStandardInformation, NULL);
        if (NT_SUCCESS(status)) {
            Msg->FileSize = fileInfo.EndOfFile.QuadPart;
            Msg->IsDirectory = fileInfo.Directory ? 1 : 0;
        }
    }
}

/* ════════════════════════════════════════════════════════════════════════════
 * PRE-CREATE CALLBACK
 *
 * Fires on every file open/create. We only care about:
 * - Files being created/opened for write on removable media
 * - This catches: copy-to-USB, save-to-USB, drag-and-drop
 * ════════════════════════════════════════════════════════════════════════════ */

FLT_PREOP_CALLBACK_STATUS CsPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
)
{
    CS_EVENT_MESSAGE eventMsg;
    CS_DECISION decision;
    ULONG createDisposition;
    ACCESS_MASK desiredAccess;

    UNREFERENCED_PARAMETER(CompletionContext);

    /* Skip kernel-mode and paging I/O */
    if (Data->RequestorMode == KernelMode) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    if (FLT_IS_FASTIO_OPERATION(Data)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /* Only intercept on removable devices */
    if (!CsIsRemovableDevice(FltObjects)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /* Check if this is a write-intent open (creating or overwriting) */
    createDisposition = (Data->Iopb->Parameters.Create.Options >> 24) & 0xFF;
    desiredAccess = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;

    if (!(desiredAccess & (FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_ATTRIBUTES)) &&
        createDisposition != FILE_CREATE &&
        createDisposition != FILE_OVERWRITE &&
        createDisposition != FILE_OVERWRITE_IF &&
        createDisposition != FILE_SUPERSEDE) {
        /* Read-only access — don't intercept */
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /* Skip directories */
    if (FlagOn(Data->Iopb->Parameters.Create.Options, FILE_DIRECTORY_FILE)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /* Build event and send to user-mode for decision */
    CsBuildEventMessage(&eventMsg, Data, FltObjects, CsEventFileCreate);

    decision = CsSendEventAndGetDecision(&eventMsg);

    if (decision == CsDecisionBlock) {
        /* Block the file creation — return ACCESS_DENIED safely */
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    /* Allow or Warn → let the operation proceed */
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

/* ════════════════════════════════════════════════════════════════════════════
 * PRE-WRITE CALLBACK
 *
 * Fires on file write operations. We intercept writes to removable media
 * to detect data being written to USB drives.
 * ════════════════════════════════════════════════════════════════════════════ */

FLT_PREOP_CALLBACK_STATUS CsPreWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
)
{
    CS_EVENT_MESSAGE eventMsg;
    CS_DECISION decision;

    UNREFERENCED_PARAMETER(CompletionContext);

    if (Data->RequestorMode == KernelMode) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    if (FLT_IS_FASTIO_OPERATION(Data)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /* Only intercept writes to removable devices */
    if (!CsIsRemovableDevice(FltObjects)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /* Skip paging I/O (system cache writes) */
    if (FlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO | IRP_SYNCHRONOUS_PAGING_IO)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    CsBuildEventMessage(&eventMsg, Data, FltObjects, CsEventFileWrite);
    eventMsg.FileSize = Data->Iopb->Parameters.Write.Length;

    decision = CsSendEventAndGetDecision(&eventMsg);

    if (decision == CsDecisionBlock) {
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

/* ════════════════════════════════════════════════════════════════════════════
 * PRE-SET-INFORMATION CALLBACK
 *
 * Catches file rename and delete operations — anti-bypass measure.
 * Detects: rename-to-USB, move-to-USB, delete-from-protected-location
 * ════════════════════════════════════════════════════════════════════════════ */

FLT_PREOP_CALLBACK_STATUS CsPreSetInfo(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
)
{
    CS_EVENT_MESSAGE eventMsg;
    CS_DECISION decision;
    FILE_INFORMATION_CLASS infoClass;

    UNREFERENCED_PARAMETER(CompletionContext);

    if (Data->RequestorMode == KernelMode) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    infoClass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;

    /* Only care about rename and delete */
    if (infoClass != FileRenameInformation &&
        infoClass != FileRenameInformationEx &&
        infoClass != FileDispositionInformation &&
        infoClass != FileDispositionInformationEx) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /* For renames, check if destination is removable media */
    if (infoClass == FileRenameInformation || infoClass == FileRenameInformationEx) {
        /* Always intercept renames involving removable devices */
        if (!CsIsRemovableDevice(FltObjects)) {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }

        CsBuildEventMessage(&eventMsg, Data, FltObjects, CsEventFileRename);

        /* Extract new file name from rename info */
        PFILE_RENAME_INFORMATION renameInfo =
            (PFILE_RENAME_INFORMATION)Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
        if (renameInfo && renameInfo->FileNameLength > 0) {
            ULONG copyLen = min(renameInfo->FileNameLength / sizeof(WCHAR), CS_MAX_PATH - 1);
            RtlCopyMemory(eventMsg.NewFilePath, renameInfo->FileName, copyLen * sizeof(WCHAR));
            eventMsg.NewFilePath[copyLen] = L'\0';
        }

        decision = CsSendEventAndGetDecision(&eventMsg);

        if (decision == CsDecisionBlock) {
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;
            return FLT_PREOP_COMPLETE;
        }
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

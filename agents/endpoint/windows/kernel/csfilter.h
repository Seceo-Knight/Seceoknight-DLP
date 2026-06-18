/**
 * CyberSentinel DLP Minifilter - Shared Header (v2)
 *
 * Shared between kernel driver and user-mode service.
 * Defines communication structures for the filter port.
 *
 * Changes from v1:
 *   - Added CsEventClipboardCapture, CsEventScreenCapture event types
 *   - Added USB device identification fields (VendorId, ProductId, SerialNumber)
 *   - Added CaptureToolName for screen capture attribution
 *   - Added ContentHash field for fingerprinting support
 *   - Added CsDecisionEncrypt, CsDecisionClearClipboard decisions
 */

#ifndef _CSFILTER_H_
#define _CSFILTER_H_

/* ────────────────────────────────────────────────────────────────────────────
 * Communication Port Names
 * ──────────────────────────────────────────────────────────────────────────── */

#define CS_FILTER_PORT_NAME     L"\\CyberSentinelPort"
#define CS_FILTER_DRIVER_NAME   L"CyberSentinelFilter"

/* ────────────────────────────────────────────────────────────────────────────
 * Limits
 * ──────────────────────────────────────────────────────────────────────────── */

#define CS_MAX_PATH             520
#define CS_MAX_VOLUME_NAME      64
#define CS_MAX_SID_LENGTH       128
#define CS_MAX_PROCESS_NAME     260
#define CS_MAX_USB_STRING       128
#define CS_MAX_HASH_LENGTH      65   /* SHA-256 hex + null */
#define CS_MAX_TOOL_NAME        128

/* ────────────────────────────────────────────────────────────────────────────
 * Event Types (kernel → usermode)
 * ──────────────────────────────────────────────────────────────────────────── */

typedef enum _CS_EVENT_TYPE {
    /* File operations */
    CsEventFileCreate           = 1,
    CsEventFileWrite            = 2,
    CsEventFileRename           = 3,
    CsEventFileDelete           = 4,

    /* USB device lifecycle */
    CsEventUsbArrival           = 10,
    CsEventUsbRemoval           = 11,
    CsEventUsbFileTransfer      = 12,

    /* Clipboard */
    CsEventClipboardCapture     = 20,

    /* Screen capture */
    CsEventScreenCapture        = 30,

    /* Print */
    CsEventPrintJob             = 40,
} CS_EVENT_TYPE;

/* ────────────────────────────────────────────────────────────────────────────
 * Device Type Flags (bitmask)
 * ──────────────────────────────────────────────────────────────────────────── */

typedef enum _CS_DEVICE_FLAGS {
    CsDeviceFixed               = 0x0001,
    CsDeviceRemovable           = 0x0002,
    CsDeviceNetwork             = 0x0004,
    CsDeviceOptical             = 0x0008,
    CsDeviceVirtual             = 0x0010,
    CsDeviceUnknown             = 0x8000,
} CS_DEVICE_FLAGS;

/* ────────────────────────────────────────────────────────────────────────────
 * Decision (usermode → kernel)
 * ──────────────────────────────────────────────────────────────────────────── */

typedef enum _CS_DECISION {
    CsDecisionAllow             = 0,
    CsDecisionBlock             = 1,
    CsDecisionWarn              = 2,   /* Allow but notify user */
    CsDecisionEncrypt           = 3,   /* Allow but encrypt the data */
    CsDecisionClearClipboard    = 4,   /* Clear clipboard content */
} CS_DECISION;

/* ────────────────────────────────────────────────────────────────────────────
 * Message: Kernel → Usermode (event notification)
 * ──────────────────────────────────────────────────────────────────────────── */

#pragma pack(push, 1)

typedef struct _CS_EVENT_MESSAGE {
    /* Header */
    ULONG           MessageId;
    CS_EVENT_TYPE   EventType;
    LARGE_INTEGER   Timestamp;          /* KeQuerySystemTimePrecise() */

    /* Process context */
    ULONG           ProcessId;
    ULONG           ThreadId;
    WCHAR           ProcessName[CS_MAX_PROCESS_NAME];

    /* User context */
    WCHAR           UserSid[CS_MAX_SID_LENGTH];

    /* File context */
    WCHAR           FilePath[CS_MAX_PATH];
    LONGLONG        FileSize;
    ULONG           FileAttributes;

    /* Volume/device context */
    WCHAR           VolumeName[CS_MAX_VOLUME_NAME];
    CS_DEVICE_FLAGS DeviceFlags;

    /* USB device identification (populated for USB events) */
    WCHAR           UsbVendorId[CS_MAX_USB_STRING];
    WCHAR           UsbProductId[CS_MAX_USB_STRING];
    WCHAR           UsbSerialNumber[CS_MAX_USB_STRING];
    WCHAR           UsbDeviceName[CS_MAX_USB_STRING];

    /* Rename-specific (valid when EventType == CsEventFileRename) */
    WCHAR           NewFilePath[CS_MAX_PATH];

    /* Screen capture tool attribution */
    WCHAR           CaptureToolName[CS_MAX_TOOL_NAME];

    /* Content fingerprint (SHA-256 hex, populated by user-mode enrichment) */
    CHAR            ContentHash[CS_MAX_HASH_LENGTH];

    /* Flags */
    ULONG           IsDirectory : 1;
    ULONG           IsPreOperation : 1;
    ULONG           NeedsDecision : 1;
    ULONG           IsClipboardText : 1;
    ULONG           Reserved : 28;

} CS_EVENT_MESSAGE, *PCS_EVENT_MESSAGE;

/* ────────────────────────────────────────────────────────────────────────────
 * Reply: Usermode → Kernel (enforcement decision)
 * ──────────────────────────────────────────────────────────────────────────── */

typedef struct _CS_DECISION_REPLY {
    ULONG           MessageId;      /* Must match the event's MessageId */
    CS_DECISION     Decision;
    ULONG           ReasonCode;     /* 0 = policy, 1 = classification, 2 = fingerprint */
} CS_DECISION_REPLY, *PCS_DECISION_REPLY;

#pragma pack(pop)

#endif /* _CSFILTER_H_ */

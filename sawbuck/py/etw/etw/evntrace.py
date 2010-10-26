#!python
# Copyright 2009 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""This file contains declarations gleaned from the evntrace.h file from
the Platform SDK. Many of the ct.Structures here are simplified from their
Platform SDK version by not in-lining one of the options of unions they
contain.
"""

import ctypes as ct
import ctypes.wintypes as wt
import exceptions
from guiddef import GUID
import winerror


TRACEHANDLE = ct.c_uint64

# from wmistr.h

# WNODE_HEADER flags are defined as follows
WNODE_FLAG_ALL_DATA = 0x00000001  # set for WNODE_ALL_DATA
WNODE_FLAG_SINGLE_INSTANCE = 0x00000002  # set for WNODE_SINGLE_INSTANCE
WNODE_FLAG_SINGLE_ITEM = 0x00000004  # set for WNODE_SINGLE_ITEM
WNODE_FLAG_EVENT_ITEM = 0x00000008  # set for WNODE_EVENT_ITEM

# Set if data block size is
# identical for all instances
# (used with  WNODE_ALL_DATA
# only)
WNODE_FLAG_FIXED_INSTANCE_SIZE = 0x00000010
WNODE_FLAG_TOO_SMALL = 0x00000020  # set for WNODE_TOO_SMALL

# Set when a data provider returns a
# WNODE_ALL_DATA in which the number of
# instances and their names returned
# are identical to those returned from the
# previous WNODE_ALL_DATA query. Only data
# blocks registered with dynamic instance
# names should use this flag.
WNODE_FLAG_INSTANCES_SAME = 0x00000040

# Instance names are not specified in
# WNODE_ALL_DATA; values specified at
# registration are used instead. Always
# set for guids registered with static
# instance names
WNODE_FLAG_STATIC_INSTANCE_NAMES = 0x00000080
WNODE_FLAG_INTERNAL = 0x00000100  # Used internally by WMI

# timestamp should not be modified by
# a historical logger
WNODE_FLAG_USE_TIMESTAMP = 0x00000200
WNODE_FLAG_PERSIST_EVENT = 0x00000400
WNODE_FLAG_EVENT_REFERENCE = 0x00002000

# Set if Instance names are ansi. Only set when returning from
# WMIQuerySingleInstanceA and WMIQueryAllDataA
WNODE_FLAG_ANSI_INSTANCENAMES = 0x00004000

# Set if WNODE is a method call
WNODE_FLAG_METHOD_ITEM = 0x00008000

# Set if instance names originated from a PDO
WNODE_FLAG_PDO_INSTANCE_NAMES = 0x00010000

# The second byte, except the first bit is used exclusively for tracing
WNODE_FLAG_TRACED_GUID = 0x00020000  # denotes a trace
WNODE_FLAG_LOG_WNODE = 0x00040000  # request to log Wnode
WNODE_FLAG_USE_GUID_PTR = 0x00080000  # Guid is actually a pointer
WNODE_FLAG_USE_MOF_PTR = 0x00100000  # MOF data are dereferenced

WNODE_FLAG_NO_HEADER = 0x00200000  # Trace without header
WNODE_FLAG_SEND_DATA_BLOCK = 0x00400000  # Data Block delivery

# Set for events that are WNODE_EVENT_REFERENCE
# Mask for event severity level. Level 0xff is the most severe type of event
WNODE_FLAG_SEVERITY_MASK = 0xff000000


# From evntrace.h
WMI_GET_ALL_DATA = 0
WMI_GET_SINGLE_INSTANCE = 1
WMI_SET_SINGLE_INSTANCE = 2
WMI_SET_SINGLE_ITEM = 3
WMI_ENABLE_EVENTS = 4
WMI_DISABLE_EVENTS  = 5
WMI_ENABLE_COLLECTION = 6
WMI_DISABLE_COLLECTION = 7
WMI_REGINFO = 8
WMI_EXECUTE_METHOD = 9
WMI_CAPTURE_STATE = 10


#
# EventTraceGuid is used to identify a event tracing session
#
EventTraceGuid = GUID('{68fdd900-4a3e-11d1-84f4-0000f80464e3}')

#
# SystemTraceControlGuid. Used to specify event tracing for kernel
#
SystemTraceControlGuid = GUID('{9e814aad-3204-11d2-9a82-006008a86939}')

#
# EventTraceConfigGuid. Used to report system configuration records
#
EventTraceConfigGuid = GUID('{01853a65-418f-4f36-aefc-dc0f1d2fd235}')

#
# DefaultTraceSecurityGuid. Specifies the default event tracing security
#
DefaultTraceSecurityGuid = GUID('{0811c1af-7a07-4a06-82ed-869455cdf713}')

KERNEL_LOGGER_NAME = "NT Kernel Logger"
GLOBAL_LOGGER_NAME = "GlobalLogger"
EVENT_LOGGER_NAME =" EventLog"
DIAG_LOGGER_NAME = "DiagLog"

MAX_MOF_FIELDS = 16  # Limit of USE_MOF_PTR fields


# types for event data going to System Event Logger
SYSTEM_EVENT_TYPE = 1

#
# predefined generic event types (0x00 to 0x09 reserved).
#

EVENT_TRACE_TYPE_INFO = 0x00  # Info or point event
EVENT_TRACE_TYPE_START = 0x01  # Start event
EVENT_TRACE_TYPE_END = 0x02  # End event
EVENT_TRACE_TYPE_STOP = 0x02  # Stop event (WinEvent compatible)
EVENT_TRACE_TYPE_DC_START = 0x03  # Collection start marker
EVENT_TRACE_TYPE_DC_END = 0x04  # Collection end marker
EVENT_TRACE_TYPE_EXTENSION = 0x05  # Extension/continuation
EVENT_TRACE_TYPE_REPLY = 0x06  # Reply event
EVENT_TRACE_TYPE_DEQUEUE = 0x07  # De-queue event
EVENT_TRACE_TYPE_RESUME = 0x07  # Resume event (WinEvent compatible)
EVENT_TRACE_TYPE_CHECKPOINT = 0x08  # Generic checkpoint event
EVENT_TRACE_TYPE_SUSPEND = 0x08  # Suspend event (WinEvent compatible)
EVENT_TRACE_TYPE_WINEVT_SEND = 0x09  # Send Event (WinEvent compatible)
EVENT_TRACE_TYPE_WINEVT_RECEIVE = 0XF0  # Receive Event (WinEvent compatible)

#
# Predefined Event Tracing Levels for Software/Debug Tracing
#
#
# Trace Level is UCHAR and passed in through the EnableLevel parameter
# in EnableTrace API. It is retrieved by the provider using the
# GetTraceEnableLevel macro.It should be interpreted as an integer value
# to mean everything at or below that level will be traced.
#
# Here are the possible Levels.
#

TRACE_LEVEL_NONE = 0  # Tracing is not on
TRACE_LEVEL_CRITICAL = 1  # Abnormal exit or termination
TRACE_LEVEL_FATAL = 1  # Deprecated name for Abnormal exit or termination
TRACE_LEVEL_ERROR = 2  # Severe errors that need logging
TRACE_LEVEL_WARNING = 3  # Warnings such as allocation failure
TRACE_LEVEL_INFORMATION = 4  # Includes non-error cases(e.g.,Entry-Exit)
TRACE_LEVEL_VERBOSE = 5  # Detailed traces from intermediate steps
TRACE_LEVEL_RESERVED6 = 6
TRACE_LEVEL_RESERVED7 = 7
TRACE_LEVEL_RESERVED8 = 8
TRACE_LEVEL_RESERVED9 = 9


#
# Event types for Process & Threads
#

EVENT_TRACE_TYPE_LOAD = 0x0A  # Load image

#
# Event types for IO subsystem
#

EVENT_TRACE_TYPE_IO_READ = 0x0A
EVENT_TRACE_TYPE_IO_WRITE = 0x0B
EVENT_TRACE_TYPE_IO_READ_INIT = 0x0C
EVENT_TRACE_TYPE_IO_WRITE_INIT = 0x0D
EVENT_TRACE_TYPE_IO_FLUSH = 0x0E
EVENT_TRACE_TYPE_IO_FLUSH_INIT =0x0F


#
# Event types for Memory subsystem
#

EVENT_TRACE_TYPE_MM_TF = 0x0A  # Transition fault
EVENT_TRACE_TYPE_MM_DZF = 0x0B  # Demand Zero fault
EVENT_TRACE_TYPE_MM_COW = 0x0C  # Copy on Write
EVENT_TRACE_TYPE_MM_GPF = 0x0D  # Guard Page fault
EVENT_TRACE_TYPE_MM_HPF = 0x0E  # Hard page fault
EVENT_TRACE_TYPE_MM_AV = 0x0F  # Access violation

#
# Event types for Network subsystem, all protocols
#

EVENT_TRACE_TYPE_SEND = 0x0A  # Send
EVENT_TRACE_TYPE_RECEIVE = 0x0B  # Receive
EVENT_TRACE_TYPE_CONNECT = 0x0C  # Connect
EVENT_TRACE_TYPE_DISCONNECT = 0x0D  # Disconnect
EVENT_TRACE_TYPE_RETRANSMIT = 0x0E  # ReTransmit
EVENT_TRACE_TYPE_ACCEPT = 0x0F  # Accept
EVENT_TRACE_TYPE_RECONNECT = 0x10  # ReConnect
EVENT_TRACE_TYPE_CONNFAIL = 0x11  # Fail
EVENT_TRACE_TYPE_COPY_TCP = 0x12  # Copy in PendData
EVENT_TRACE_TYPE_COPY_ARP = 0x13  # NDIS_STATUS_RESOURCES Copy
EVENT_TRACE_TYPE_ACKFULL = 0x14  # A full data ACK
EVENT_TRACE_TYPE_ACKPART = 0x15  # A Partial data ACK
EVENT_TRACE_TYPE_ACKDUP = 0x16  # A Duplicate data ACK


#
# Event Types for the Header (to handle internal event headers)
#

EVENT_TRACE_TYPE_GUIDMAP = 0x0A
EVENT_TRACE_TYPE_CONFIG = 0x0B
EVENT_TRACE_TYPE_SIDINFO = 0x0C
EVENT_TRACE_TYPE_SECURITY = 0x0D

#
# Event Types for Registry subsystem
#

EVENT_TRACE_TYPE_REGCREATE = 0x0A  # NtCreateKey
EVENT_TRACE_TYPE_REGOPEN = 0x0B  # NtOpenKey
EVENT_TRACE_TYPE_REGDELETE = 0x0C  # NtDeleteKey
EVENT_TRACE_TYPE_REGQUERY = 0x0D  # NtQueryKey
EVENT_TRACE_TYPE_REGSETVALUE = 0x0E  # NtSetValueKey
EVENT_TRACE_TYPE_REGDELETEVALUE = 0x0F  # NtDeleteValueKey
EVENT_TRACE_TYPE_REGQUERYVALUE = 0x10  # NtQueryValueKey
EVENT_TRACE_TYPE_REGENUMERATEKEY = 0x11  # NtEnumerateKey
EVENT_TRACE_TYPE_REGENUMERATEVALUEKEY = 0x12  # NtEnumerateValueKey
EVENT_TRACE_TYPE_REGQUERYMULTIPLEVALUE = 0x13  # NtQueryMultipleValueKey
EVENT_TRACE_TYPE_REGSETINFORMATION = 0x14  # NtSetInformationKey
EVENT_TRACE_TYPE_REGFLUSH = 0x15  # NtFlushKey
EVENT_TRACE_TYPE_REGKCBCREATE = 0x16  # KcbCreate
EVENT_TRACE_TYPE_REGKCBDELETE = 0x17  # KcbDelete
EVENT_TRACE_TYPE_REGKCBRUNDOWNBEGIN = 0x18  # KcbRundownBegin
EVENT_TRACE_TYPE_REGKCBRUNDOWNEND = 0x19  # KcbRundownEnd
EVENT_TRACE_TYPE_REGVIRTUALIZE = 0x1A  # VirtualizeKey
EVENT_TRACE_TYPE_REGCLOSE = 0x1B  # NtClose (KeyObject)
EVENT_TRACE_TYPE_REGSETSECURITY = 0x1C  # SetSecurityDescriptor (KeyObject)
EVENT_TRACE_TYPE_REGQUERYSECURITY = 0x1D  # QuerySecurityDescriptor (KeyObject)
# CmKtmNotification (TRANSACTION_NOTIFY_COMMIT)
EVENT_TRACE_TYPE_REGCOMMIT = 0x1E
# CmKtmNotification (TRANSACTION_NOTIFY_PREPARE)
EVENT_TRACE_TYPE_REGPREPARE = 0x1F
# CmKtmNotification (TRANSACTION_NOTIFY_ROLLBACK)
EVENT_TRACE_TYPE_REGROLLBACK = 0x20
EVENT_TRACE_TYPE_REGMOUNTHIVE = 0x21  # NtLoadKey variations + system hives

#
# Event types for system configuration records
#
EVENT_TRACE_TYPE_CONFIG_CPU = 0x0A  # CPU Configuration
EVENT_TRACE_TYPE_CONFIG_PHYSICALDISK = 0x0B  # Physical Disk Configuration
EVENT_TRACE_TYPE_CONFIG_LOGICALDISK = 0x0C  # Logical Disk Configuration
EVENT_TRACE_TYPE_CONFIG_NIC = 0x0D  # NIC Configuration
EVENT_TRACE_TYPE_CONFIG_VIDEO = 0x0E  # Video Adapter Configuration
EVENT_TRACE_TYPE_CONFIG_SERVICES = 0x0F  # Active Services
EVENT_TRACE_TYPE_CONFIG_POWER = 0x10  # ACPI Configuration
EVENT_TRACE_TYPE_CONFIG_NETINFO = 0x11  # Networking Configuration

EVENT_TRACE_TYPE_CONFIG_IRQ = 0x15  # IRQ assigned to devices
EVENT_TRACE_TYPE_CONFIG_PNP = 0x16  # PnP device info
  # Primary/Secondary IDE channel Configuration
EVENT_TRACE_TYPE_CONFIG_IDECHANNEL = 0x17
EVENT_TRACE_TYPE_CONFIG_PLATFORM = 0x19  # Platform Configuration

#
# Enable flags for Kernel Events
#
EVENT_TRACE_FLAG_PROCESS = 0x00000001  # process start & end
EVENT_TRACE_FLAG_THREAD = 0x00000002  # thread start & end
EVENT_TRACE_FLAG_IMAGE_LOAD = 0x00000004  # image load

EVENT_TRACE_FLAG_DISK_IO = 0x00000100  # physical disk IO
EVENT_TRACE_FLAG_DISK_FILE_IO = 0x00000200  # requires disk IO

EVENT_TRACE_FLAG_MEMORY_PAGE_FAULTS = 0x00001000  # all page faults
EVENT_TRACE_FLAG_MEMORY_HARD_FAULTS = 0x00002000  # hard faults only

EVENT_TRACE_FLAG_NETWORK_TCPIP = 0x00010000  # tcpip send & receive

EVENT_TRACE_FLAG_REGISTRY = 0x00020000  # registry calls
EVENT_TRACE_FLAG_DBGPRINT = 0x00040000  # DbgPrint(ex) Calls

#
# Enable flags for Kernel Events on Vista and above
#
EVENT_TRACE_FLAG_PROCESS_COUNTERS = 0x00000008  # process perf counters
EVENT_TRACE_FLAG_CSWITCH = 0x00000010  # context switches
EVENT_TRACE_FLAG_DPC = 0x00000020  # deffered procedure calls
EVENT_TRACE_FLAG_INTERRUPT = 0x00000040  # interrupts
EVENT_TRACE_FLAG_SYSTEMCALL = 0x00000080  # system calls

EVENT_TRACE_FLAG_DISK_IO_INIT = 0x00000400  # physical disk IO initiation

EVENT_TRACE_FLAG_ALPC = 0x00100000  # ALPC traces
EVENT_TRACE_FLAG_SPLIT_IO = 0x00200000  # split io traces (VolumeManager)

EVENT_TRACE_FLAG_DRIVER = 0x00800000  # driver delays
EVENT_TRACE_FLAG_PROFILE = 0x01000000  # sample based profiling
EVENT_TRACE_FLAG_FILE_IO = 0x02000000  # file IO
EVENT_TRACE_FLAG_FILE_IO_INIT = 0x04000000  # file IO initiation

#
# Enable flags for Kernel Events on Win7 and above
#
EVENT_TRACE_FLAG_DISPATCHER = 0x00000800  # scheduler (ReadyThread)
EVENT_TRACE_FLAG_VIRTUAL_ALLOC = 0x00004000  # VM operations

#
# Pre-defined Enable flags for everybody else
#
EVENT_TRACE_FLAG_EXTENSION = 0x80000000  # Indicates more flags
EVENT_TRACE_FLAG_FORWARD_WMI = 0x40000000  # Can forward to WMI
EVENT_TRACE_FLAG_ENABLE_RESERVE = 0x20000000  # Reserved

#
# Logger Mode flags
#
EVENT_TRACE_FILE_MODE_NONE = 0x00000000  # Logfile is off
EVENT_TRACE_FILE_MODE_SEQUENTIAL = 0x00000001  # Log sequentially
EVENT_TRACE_FILE_MODE_CIRCULAR = 0x00000002  # Log in circular manner
EVENT_TRACE_FILE_MODE_APPEND = 0x00000004  # Append sequential log

EVENT_TRACE_REAL_TIME_MODE = 0x00000100  # Real time mode on
EVENT_TRACE_DELAY_OPEN_FILE_MODE = 0x00000200  # Delay opening file
EVENT_TRACE_BUFFERING_MODE = 0x00000400  # Buffering mode only
EVENT_TRACE_PRIVATE_LOGGER_MODE = 0x00000800  # Process Private Logger
EVENT_TRACE_ADD_HEADER_MODE = 0x00001000  # Add a logfile header

EVENT_TRACE_USE_GLOBAL_SEQUENCE = 0x00004000  # Use global sequence no.
EVENT_TRACE_USE_LOCAL_SEQUENCE = 0x00008000  # Use local sequence no.

EVENT_TRACE_RELOG_MODE = 0x00010000  # Relogger

EVENT_TRACE_USE_PAGED_MEMORY = 0x01000000  # Use pageable buffers

#
# Logger Mode flags on XP and above
#
EVENT_TRACE_FILE_MODE_NEWFILE = 0x00000008  # Auto-switch log file
EVENT_TRACE_FILE_MODE_PREALLOCATE = 0x00000020  # Pre-allocate mode

#
# Logger Mode flags on Vista and above
#
# Session cannot be stopped (Autologger only)
EVENT_TRACE_NONSTOPPABLE_MODE = 0x00000040
EVENT_TRACE_SECURE_MODE = 0x00000080  # Secure session
EVENT_TRACE_USE_KBYTES_FOR_SIZE = 0x00002000  # Use KBytes as file size unit
EVENT_TRACE_PRIVATE_IN_PROC = 0x00020000  # In process private logger
# Reserved bit, used to signal Heap/Critsec tracing
EVENT_TRACE_MODE_RESERVED = 0x00100000

#
# Logger Mode flags on Win7 and above
#
# Use this for low frequency sessions.
EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING = 0x10000000

#
# ControlTrace Codes
#
EVENT_TRACE_CONTROL_QUERY = 0
EVENT_TRACE_CONTROL_STOP = 1
EVENT_TRACE_CONTROL_UPDATE = 2

#
# Flush ControlTrace Codes for XP and above
#
EVENT_TRACE_CONTROL_FLUSH = 3  # Flushes all the buffers

#
# Flags used by WMI Trace Message
# Note that the order or value of these flags should NOT be changed
# as they are processed
# in this order.
#
TRACE_MESSAGE_SEQUENCE = 1  # Message should include a sequence number
TRACE_MESSAGE_GUID = 2  # Message includes a GUID
TRACE_MESSAGE_COMPONENTID = 4  # Message has no GUID, Component ID instead
TRACE_MESSAGE_TIMESTAMP = 8  # Message includes a timestamp
# *Obsolete* Clock type is controlled by the logger
TRACE_MESSAGE_PERFORMANCE_TIMESTAMP = 16
TRACE_MESSAGE_SYSTEMINFO = 32  # Message includes system information TID,PID

#
# Vista flags set by system to indicate provider pointer size.
#

TRACE_MESSAGE_POINTER32 = 0x0040  # Message logged by 32 bit provider
TRACE_MESSAGE_POINTER64 = 0x0080  # Message logged by 64 bit provider

# Only the lower 16 bits of flags are placed in the message
# those above 16 bits are reserved for local processing
TRACE_MESSAGE_FLAG_MASK = 0xFFFF

# the maximum size allowed for a single trace message
# longer messages will return ERROR_BUFFER_OVERFLOW
TRACE_MESSAGE_MAXIMUM_SIZE = 8*1024

#
# Flags to indicate to consumer which fields
# in the EVENT_TRACE_HEADER are valid
#

EVENT_TRACE_USE_PROCTIME = 0x0001  # ProcessorTime field is valid
EVENT_TRACE_USE_NOCPUTIME = 0x0002  # No Kernel/User/Processor Times

#
# TRACE_HEADER_FLAG values are used in the Flags field of EVENT_TRACE_HEADER
# ct.Structure while calling into TraceEvent API
#

TRACE_HEADER_FLAG_USE_TIMESTAMP = 0x00000200
TRACE_HEADER_FLAG_TRACED_GUID = 0x00020000  # denotes a trace
TRACE_HEADER_FLAG_LOG_WNODE = 0x00040000  # request to log Wnode
TRACE_HEADER_FLAG_USE_GUID_PTR = 0x00080000  # Guid is actually a pointer
TRACE_HEADER_FLAG_USE_MOF_PTR = 0x00100000  # MOF data are dereferenced


class WNODE_HEADER(ct.Structure):
  _fields_ = [('BufferSize', ct.c_ulong),
              ('ProviderId', ct.c_ulong),
              ('HistoricalContext', ct.c_uint64),
              ('TimeStamp', wt.LARGE_INTEGER),
              ('Guid', GUID),
              ('ClientContext', ct.c_ulong),
              ('Flags', ct.c_ulong)]


class EVENT_TRACE_PROPERTIES(ct.Structure):
  _fields_ = [('Wnode', WNODE_HEADER),
              ('BufferSize', ct.c_ulong),
              ('MinimumBuffers', ct.c_ulong),
              ('MaximumBuffers', ct.c_ulong),
              ('MaximumFileSize', ct.c_ulong),
              ('LogFileMode', ct.c_ulong),
              ('FlushTimer', ct.c_ulong),
              ('EnableFlags', ct.c_ulong),
              ('AgeLimit', ct.c_long),
              ('NumberOfBuffers', ct.c_ulong),
              ('FreeBuffers', ct.c_ulong),
              ('EventsLost', ct.c_ulong),
              ('BuffersWritten', ct.c_ulong),
              ('LogBuffersLost', ct.c_ulong),
              ('RealTimeBuffersLost', ct.c_ulong),
              ('LoggerThreadId', wt.HANDLE),
              ('LogFileNameOffset', ct.c_ulong),
              ('LoggerNameOffset', ct.c_ulong)]


class TRACE_GUID_REGISTRATION(ct.Structure):
  _fields_ = [('Guid', ct.POINTER(GUID)),
               ('RegHandle', wt.HANDLE)]


class EVENT_TRACE_HEADER_CLASS(ct.Structure):
  _fields_ = [('Type', ct.c_ubyte),
              ('Level', ct.c_ubyte),
              ('Version', ct.c_uint16)]


class EVENT_TRACE_HEADER(ct.Structure):
  _fields_ = [('Size', ct.c_ushort),
              ('HeaderType', ct.c_ubyte),
              ('MarkerFlags', ct.c_ubyte),
              ('Class', EVENT_TRACE_HEADER_CLASS),
              ('ThreadId', ct.c_ulong),
              ('ProcessId', ct.c_ulong),
              ('TimeStamp', wt.LARGE_INTEGER),
              ('Guid', GUID),
              ('ClientContext', ct.c_ulong),
              ('Flags', ct.c_ulong)]


class MOF_FIELD(ct.Structure):
  _fields_ = [('DataPtr', ct.c_ulonglong),
              ('Length', ct.c_ulong),
              ('DataType', ct.c_ulong)]


class EVENT_TRACE(ct.Structure):
  _fields_ = [('Header', EVENT_TRACE_HEADER),
              ('InstanceId', ct.c_ulong),
              ('ParentInstanceId', ct.c_ulong),
              ('ParentGuid', GUID),
              ('MofData', ct.c_void_p),
              ('MofLength', ct.c_ulong),
              ('ClientContext', ct.c_ulong)]


class SYSTEMTIME(ct.Structure):
  _fields_ = [('wYear', wt.WORD),
              ('wMonth', wt.WORD),
              ('wDayOfWeek', wt.WORD),
              ('wDay', wt.WORD),
              ('wHour', wt.WORD),
              ('wMinute', wt.WORD),
              ('wSecond', wt.WORD),
              ('wMilliseconds', wt.WORD)]


class TIME_ZONE_INFORMATION(ct.Structure):
  _fields_ = [('Bias', ct.c_long),
              ('StandardName', ct.c_wchar * 32),
              ('StandardDate', SYSTEMTIME),
              ('StandardBias', ct.c_long),
              ('DaylightName', ct.c_wchar * 32),
              ('DaylightDate', SYSTEMTIME),
              ('DaylightBias', ct.c_long)]


class TRACE_LOGFILE_HEADER(ct.Structure):
  _fields_ = [('BufferSize', ct.c_ulong),
              ('MajorVersion', ct.c_byte),
              ('MinorVersion', ct.c_byte),
              ('SubVersion', ct.c_byte),
              ('SubMinorVersion', ct.c_byte),
              ('ProviderVersion', ct.c_ulong),
              ('NumberOfProcessors', ct.c_ulong),
              ('EndTime', wt.LARGE_INTEGER),
              ('TimerResolution', ct.c_ulong),
              ('MaximumFileSize', ct.c_ulong),
              ('LogFileMode', ct.c_ulong),
              ('BuffersWritten', ct.c_ulong),
              ('StartBuffers', ct.c_ulong),
              ('PointerSize', ct.c_ulong),
              ('EventsLost', ct.c_ulong),
              ('CpuSpeedInMHz', ct.c_ulong),
              ('LoggerName', ct.c_wchar_p),
              ('LogFileName', ct.c_wchar_p),
              ('TimeZone', TIME_ZONE_INFORMATION),
              ('BootTime', wt.LARGE_INTEGER),
              ('PerfFreq', wt.LARGE_INTEGER),
              ('StartTime', wt.LARGE_INTEGER),
              ('ReservedFlags', ct.c_ulong),
              ('BuffersLost', ct.c_ulong)]


# This must be "forward declared", because of the callback type below,
# which is contained in the ct.Structure.
class EVENT_TRACE_LOGFILE(ct.Structure):
  pass


# The type for event trace callbacks.
EVENT_CALLBACK = ct.WINFUNCTYPE(None, ct.POINTER(EVENT_TRACE))
EVENT_TRACE_BUFFER_CALLBACK = ct.WINFUNCTYPE(ct.c_ulong,
                                             ct.POINTER(EVENT_TRACE_LOGFILE))


EVENT_TRACE_LOGFILE._fields_ = [
    ('LogFileName', ct.c_wchar_p),
    ('LoggerName', ct.c_wchar_p),
    ('CurrentTime', ct.c_longlong),
    ('BuffersRead', ct.c_ulong),
    ('ProcessTraceMode', ct.c_ulong),
    ('CurrentEvent', EVENT_TRACE),
    ('LogfileHeader', TRACE_LOGFILE_HEADER),
    ('BufferCallback', EVENT_TRACE_BUFFER_CALLBACK),
    ('BufferSize', ct.c_ulong),
    ('Filled', ct.c_ulong),
    ('EventsLost', ct.c_ulong),
    ('EventCallback', EVENT_CALLBACK),
    ('IsKernelTrace', ct.c_ulong),
    ('Context', ct.c_void_p)]


def CheckWinError(result, func, arguments):
  if result != winerror.ERROR_SUCCESS:
    raise exceptions.WindowsError(result)


StartTrace = ct.windll.advapi32.StartTraceW
StartTrace.argtypes = [ct.POINTER(TRACEHANDLE),
                       ct.c_wchar_p,
                       ct.POINTER(EVENT_TRACE_PROPERTIES)]
StartTrace.restype = ct.c_ulong
StartTrace.errcheck = CheckWinError


ControlTrace = ct.windll.advapi32.ControlTraceW
ControlTrace.argtypes = [TRACEHANDLE,
                         ct.c_wchar_p,
                         ct.POINTER(EVENT_TRACE_PROPERTIES),
                         ct.c_ulong]
ControlTrace.restype = ct.c_ulong
ControlTrace.errcheck = CheckWinError


EnableTrace = ct.windll.advapi32.EnableTrace
EnableTrace.argtypes = [ct.c_ulong,
                        ct.c_ulong,
                        ct.c_ulong,
                        ct.POINTER(GUID),
                        TRACEHANDLE]
EnableTrace.restype = ct.c_ulong
EnableTrace.errcheck = CheckWinError


WMIDPREQUEST = ct.WINFUNCTYPE(ct.c_ulong,
                              ct.c_ulong,
                              ct.c_void_p,
                              ct.c_ulong,
                              ct.c_void_p)


RegisterTraceGuids = ct.windll.advapi32.RegisterTraceGuidsW
RegisterTraceGuids.argtypes = [WMIDPREQUEST,   # RequestAddress
                               ct.c_void_p,  # RequestContext
                               ct.POINTER(GUID),  # ControlGuid
                               ct.c_ulong,  # GuidCount
                               # TraceGuidReg
                               ct.POINTER(TRACE_GUID_REGISTRATION),
                               ct.c_wchar_p,  # MofImagePath
                               ct.c_wchar_p,  # MofResourceName
                               ct.POINTER(TRACEHANDLE)]  # RegistrationHandle
RegisterTraceGuids.restype = ct.c_ulong
RegisterTraceGuids.errcheck = CheckWinError


UnregisterTraceGuids = ct.windll.advapi32.UnregisterTraceGuids
UnregisterTraceGuids.argtypes = [TRACEHANDLE]
UnregisterTraceGuids.restype = ct.c_ulong
UnregisterTraceGuids.errcheck = CheckWinError


GetTraceLoggerHandle = ct.windll.advapi32.GetTraceLoggerHandle
GetTraceLoggerHandle.argtypes = [ct.c_void_p]
GetTraceLoggerHandle.restype = TRACEHANDLE


GetTraceEnableFlags = ct.windll.advapi32.GetTraceEnableFlags
GetTraceEnableFlags.argtypes = [TRACEHANDLE]
GetTraceEnableFlags.restype = ct.c_ulong


GetTraceEnableLevel = ct.windll.advapi32.GetTraceEnableLevel
GetTraceEnableLevel.argtypes = [TRACEHANDLE]
GetTraceEnableLevel.restype = ct.c_ubyte


TraceEvent = ct.windll.advapi32.TraceEvent
TraceEvent.argtypes = [TRACEHANDLE, ct.POINTER(EVENT_TRACE_HEADER)]
TraceEvent.restype = ct.c_ulong
TraceEvent.errcheck = CheckWinError


def CheckTraceHandle(result, func, arguments):
  if result == ct.c_ulong(-1).value:
    raise exceptions.WindowsError(ct.GetLastError())

  return result


OpenTrace = ct.windll.advapi32.OpenTraceW
OpenTrace.argtypes = [ct.POINTER(EVENT_TRACE_LOGFILE)]
OpenTrace.restype = TRACEHANDLE
OpenTrace.errcheck = CheckTraceHandle


ProcessTrace = ct.windll.advapi32.ProcessTrace
ProcessTrace.argtypes = [ct.POINTER(TRACEHANDLE),
                         ct.c_ulong,
                         ct.POINTER(wt.FILETIME),
                         ct.POINTER(wt.FILETIME)]
ProcessTrace.restype = ct.c_ulong
ProcessTrace.errcheck = CheckWinError


CloseTrace = ct.windll.advapi32.CloseTrace
CloseTrace.argtypes = [TRACEHANDLE]
CloseTrace.restype = ct.c_ulong
CloseTrace.errcheck = CheckWinError

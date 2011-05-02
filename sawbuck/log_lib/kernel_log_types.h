// Copyright 2010 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// NT Kernel log structures.
#ifndef SAWBUCK_LOG_LIB_KERNEL_LOG_TYPES_H_
#define SAWBUCK_LOG_LIB_KERNEL_LOG_TYPES_H_

namespace kernel_log_types {
// These structures and GUIDs are gleaned from the system.tfm file
// that ships with Debugging Tools For Windows. In some cases the
// formats declared there are not in strict accordance with reality
// in which case there has been some sleuthing around hex dumps of
// the messages to infer the real truth.

DEFINE_GUID(kEventTraceEventClass,
  0x68fdd900, 0x4a3e, 0x11d1, 0x84, 0xf4, 0x00, 0x00, 0xf8, 0x04, 0x64, 0xe3);

enum {
  kLogFileHeaderEvent = 0,
};

struct LogFileHeader32 {
  ULONG BufferSize;
  ULONG Version;
  ULONG BuildNumber;
  ULONG NumProc;
  ULONGLONG EndTime;
  ULONG TimerResolution;
  ULONG MaxFileSize;
  ULONG LogFileMode;
  ULONG BuffersWritten;
  ULONG StartBuffers;
  ULONG PointerSize;
  ULONG EventsLost;
  ULONG CPUSpeed;
  ULONG LoggerName;
  ULONG LogFileName;
  char TimeZone[176];
  ULONGLONG BootTime;
  ULONGLONG PerfFrequency;
  ULONGLONG StartTime;
  ULONG ReservedFlags;
  ULONG BuffersLost;
};

struct LogFileHeader64 {
  ULONG BufferSize;
  ULONG Version;
  ULONG BuildNumber;
  ULONG NumProc;
  ULONGLONG EndTime;
  ULONG TimerResolution;
  ULONG MaxFileSize;
  ULONG LogFileMode;
  ULONG BuffersWritten;
  ULONG StartBuffers;
  ULONG PointerSize;
  ULONG EventsLost;
  ULONG CPUSpeed;
  ULONGLONG LoggerName;
  ULONGLONG LogFileName;
  char TimeZone[176];
  ULONGLONG BootTime;
  ULONGLONG PerfFrequency;
  ULONGLONG StartTime;
  ULONG ReservedFlags;
  ULONG BuffersLost;
};

DEFINE_GUID(kImageLoadEventClass,
  0x2cb15d1d, 0x5fc1, 0x11d2, 0xab, 0xe1, 0x00, 0xa0, 0xc9, 0x11, 0xf5, 0x18);

enum {
  kImageNotifyUnloadEvent = 2,
  kImageNotifyIsLoadedEvent = 3,
  kImageNotifyLoadEvent = 10,
};

struct ImageLoad32V0 {
  ULONG BaseAddress;
  ULONG ModuleSize;
  wchar_t ImageFileName[1];
};

struct ImageLoad64V0 {
  ULONGLONG BaseAddress;
  ULONG ModuleSize;
  wchar_t ImageFileName[1];
};

struct ImageLoad32V1 {
  ULONG BaseAddress;
  ULONG ModuleSize;
  ULONG ProcessId;
  wchar_t ImageFileName[1];
};

struct ImageLoad64V1 {
  ULONGLONG BaseAddress;
  ULONGLONG ModuleSize;
  ULONG ProcessId;
  wchar_t ImageFileName[1];
};

struct ImageLoad32V2 {
  ULONG BaseAddress;
  ULONG ModuleSize;
  ULONG ProcessId;
  ULONG ImageChecksum;
  ULONG TimeDateStamp;
  ULONG Reserved0;
  ULONG DefaultBase;
  ULONG Reserved1;
  ULONG Reserved2;
  ULONG Reserved3;
  ULONG Reserved4;
  wchar_t ImageFileName[1];
};

struct ImageLoad64V2 {
  ULONGLONG BaseAddress;
  ULONGLONG ModuleSize;
  ULONG ProcessId;
  ULONG ImageChecksum;
  ULONG TimeDateStamp;
  ULONG Reserved0;
  ULONGLONG DefaultBase;
  ULONG Reserved1;
  ULONG Reserved2;
  ULONG Reserved3;
  ULONG Reserved4;
  wchar_t ImageFileName[1];
};

// These are documented-ish at
// http://msdn.microsoft.com/en-us/library/dd765153(VS.85).aspx
DEFINE_GUID(kPageFaultEventClass,
  0x3d6fa8d3, 0xfe05, 0x11d0, 0x9d, 0xda, 0x00, 0xc0, 0x4f, 0xd7, 0xba, 0x7c);

enum {
  kTransitionFaultEvent = 10,
  kDemandZeroFaultEvent = 11,
  kCopyOnWriteEvent = 12,
  kGuardPageFaultEvent = 13,
  kHardEvent = 14,
  kAccessViolationEvent = 15,

  kHardPageFaultEvent = 32,
};

// Verified on Vista 32.
struct PageFault32V2 {
  ULONG VirtualAddress;
  ULONG ProgramCounter;
};

struct PageFault64V2 {
  ULONGLONG VirtualAddress;
  ULONGLONG ProgramCounter;
};

// Verified on Vista 32.
struct HardPageFault32V2 {
  ULONGLONG InitialTime;
  ULONGLONG ReadOffset;
  ULONG VirtualAddress;
  ULONG FileObject;
  ULONG ThreadId;
  ULONG ByteCount;
};

struct HardPageFault64V2 {
  ULONGLONG InitialTime;
  ULONGLONG ReadOffset;
  ULONGLONG VirtualAddress;
  ULONGLONG FileObject;
  ULONG ThreadId;
  ULONG ByteCount;
};


// Process-related events.

enum {
  kProcessStartEvent = 1,
  kProcessEndEvent = 2,
  kProcessIsRunningEvent = 3,
  kProcessCollectionEnded = 4,
};

DEFINE_GUID(kProcessEventClass,
  0x3d6fa8d0, 0xfe05, 0x11d0, 0x9d, 0xda, 0x00, 0xc0, 0x4f, 0xd7, 0xba, 0x7c);

// Unverified.
struct ProcessInfo32V0 {
  ULONG ProcessId;  // ItemPtr
  ULONG ParentId;  // ItemPtr
  // UserSID: ItemKSid
  // ImageFileName: ItemString
};

// Verified from XP32 SP3 logs.
struct ProcessInfo32V1 {
  ULONG PageDirectoryBase;  // ItemPtr
  ULONG ProcessId;  // ItemULong
  ULONG ParentId;  // ItemULong
  ULONG SessionId;  // ItemULong
  ULONG ExitStatus;  // ItemUlong
  ULONG Unknown1;  // ??? - ItemPtr
  ULONG Unknown2;  // ???
  SID UserSID;  // ItemKSid
  // ImageName, ItemAString
};

// Unverified.
struct ProcessInfo64V1 {
  ULONGLONG PageDirectoryBase;  // ItemPtr
  ULONG ProcessId;  // ItemULong
  ULONG ParentId;  // ItemULong
  ULONG SessionId;  // ItemULong
  ULONG ExitStatus;  // ItemUlong
  ULONGLONG Unknown1;  // ??? - ItemPtr
  ULONGLONG Unknown2;  // ???
  SID UserSID;   // ItemKSid
  // ImageFileName, ItemString
};

// Verified from Vista32 SP1 logs.
struct ProcessInfo32V2 {
  ULONG UniqueProcessKey;  // ItemPtr
  ULONG ProcessId;  // ItemULong
  ULONG ParentId;  // ItemULong
  ULONG SessionId;  // ItemULong
  ULONG ExitStatus;  // ItemUlong
  ULONG PageTable;  // ??? - ItemPtr
  ULONG Unknown;  // ???
  SID UserSID;  // ItemKSid
  // ImageName, ItemAString
  // ImageFileName, ItemString
};

// Verified from Vista64 SP1 logs.
struct ProcessInfo64V2 {
  ULONGLONG UniqueProcessKey;  // ItemPtr
  ULONG ProcessId;  // ItemULong
  ULONG ParentId;  // ItemULong
  ULONG SessionId;  // ItemULong
  ULONG ExitStatus;  // ItemUlong
  ULONGLONG PageTable;  // ??? - ItemPtr
  ULONGLONG Unknown;  // ???
  SID UserSID;  // ItemKSid
  // ImageName, ItemAString
  // ImageFileName, ItemWString
};

// Verified from Win7 32 bit logs.
struct ProcessInfo32V3 {
  ULONG UniqueProcessKey;  // ItemPtr
  ULONG ProcessId;  // ItemULong
  ULONG ParentId;  // ItemULong
  ULONG SessionId;  // ItemULong
  ULONG ExitStatus;  // ItemUlong
  ULONG PageTable;  // ItemPtr
  ULONG Unknown1;
  ULONG Unknown2;
  SID UserSID;  // ItemKSid
  // ImageName, ItemAString
  // ImageFileName, ItemWString
};

// Verified from Win7 64 bit logs.
struct ProcessInfo64V3 {
  ULONGLONG UniqueProcessKey;  // ItemPtr
  ULONG ProcessId;  // ItemULong
  ULONG ParentId;  // ItemULong
  ULONG SessionId;  // ItemULong
  ULONG ExitStatus;  // ItemUlong
  ULONGLONG PageTable;  // ItemPtr
  ULONGLONG Unknown1;
  ULONGLONG Unknown2;
  SID UserSID;  // ItemKSid
  // ImageName, ItemAString
  // ImageFileName, ItemWString
};

}  // namespace kernel_log_types

#endif  // SAWBUCK_LOG_LIB_KERNEL_LOG_TYPES_H_

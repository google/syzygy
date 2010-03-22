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
#ifndef SAWBUCK_VIEWER_KERNEL_LOG_TYPES_H_
#define SAWBUCK_VIEWER_KERNEL_LOG_TYPES_H_

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
  ULONG ModuleSize;
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
  ULONG ModuleSize;
  ULONG ProcessId;
  ULONG Reserved0;
  ULONG ImageChecksum;
  ULONG TimeDateStamp;
  ULONGLONG DefaultBase;
  ULONG Reserved1;
  ULONG Reserved2;
  ULONG Reserved3;
  ULONG Reserved4;
  wchar_t ImageFileName[1];
};

}  // namespace kernel_log_types

#endif  // SAWBUCK_VIEWER_KERNEL_LOG_TYPES_H_

// Copyright 2015 Google Inc. All Rights Reserved.
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
// Definition of some structures encountered in the PE files.

#ifndef SYZYGY_PE_PE_STRUCTS_H_
#define SYZYGY_PE_PE_STRUCTS_H_

#include <windows.h>

namespace pe {

// Redefinition of the IMAGE_LOAD_CONFIG_CODE_INTEGRITY structure. This
// corresponds to the structure as encountered in the version 10.0+ of the
// Windows SDK.
struct IMAGE_LOAD_CONFIG_CODE_INTEGRITY {
  WORD Flags;
  WORD Catalog;
  DWORD CatalogOffset;
  DWORD Reserved;
};

// Redefinition of the IMAGE_LOAD_CONFIG_DIRECTORY structure. This corresponds
// to the structure as encountered in the version 10.0.14393 of the Windows SDK.
struct LoadConfigDirectory {
  // Fields available in v8.0+ of the Windows SDK.
  DWORD   Size;
  DWORD   TimeDateStamp;
  WORD    MajorVersion;
  WORD    MinorVersion;
  DWORD   GlobalFlagsClear;
  DWORD   GlobalFlagsSet;
  DWORD   CriticalSectionDefaultTimeout;
  DWORD   DeCommitFreeBlockThreshold;
  DWORD   DeCommitTotalFreeThreshold;
  DWORD   LockPrefixTable;                // VA
  DWORD   MaximumAllocationSize;
  DWORD   VirtualMemoryThreshold;
  DWORD   ProcessHeapFlags;
  DWORD   ProcessAffinityMask;
  WORD    CSDVersion;
  WORD    Reserved1;
  DWORD   EditList;                       // VA
  DWORD   SecurityCookie;                 // VA
  DWORD   SEHandlerTable;                 // VA
  DWORD   SEHandlerCount;

  // Fields available in v8.1+ of the Windows SDK.
  DWORD   GuardCFCheckFunctionPointer;    // VA
  DWORD   Reserved2;
  DWORD   GuardCFFunctionTable;           // VA
  DWORD   GuardCFFunctionCount;
  DWORD   GuardFlags;

  // Fields available in v10.0+ of the Windows SDK.
  IMAGE_LOAD_CONFIG_CODE_INTEGRITY CodeIntegrity;
  DWORD GuardAddressTakenIatEntryTable;  // VA
  DWORD GuardAddressTakenIatEntryCount;
  DWORD GuardLongJumpTargetTable;  // VA
  DWORD GuardLongJumpTargetCount;
  DWORD DynamicValueRelocTable;  // VA
  DWORD HybridMetadataPointer;
};

// An enum mapping the size of a given IMAGE_LOAD_CONFIG_DIRECTORY structure
// to the corresponding version of the Windows SDK.
enum LoadConfigDirectoryVersion {
  kLoadConfigDirectorySizeUnknown = 0,
  // Corresponds to the version 8.0 of the Windows SDK.
  kLoadConfigDirectorySize80 =
      offsetof(LoadConfigDirectory, GuardCFCheckFunctionPointer),
  // Corresponds to the version 8.1+ of the Windows SDK.
  kLoadConfigDirectorySize81 = offsetof(LoadConfigDirectory, CodeIntegrity),
  // Corresponds to the version 10.0+ of the Windows SDK with the code integrity
  // feature disabled.
  kLoadConfigDirectorySize100NoCodeIntegrity =
      offsetof(LoadConfigDirectory, CodeIntegrity),
  // Corresponds to the version 10.0+ of the Windows SDK with the CFG feature
  // disabled.
  kLoadConfigDirectorySize100NoCFG =
      offsetof(LoadConfigDirectory, GuardAddressTakenIatEntryTable),
  // Corresponds to the full version 10.0 of the Windows SDK.
  kLoadConfigDirectorySize100 = sizeof(LoadConfigDirectory),
};

};  // namespace pe

#endif  // SYZYGY_PE_PE_STRUCTS_H_

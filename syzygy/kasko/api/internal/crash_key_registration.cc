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

#include "syzygy/kasko/api/internal/crash_key_registration.h"

#include <psapi.h>

#include <string.h>

#include <cstdint>

#include "base/logging.h"
#include "base/process/process_handle.h"
#include "base/strings/string16.h"
#include "syzygy/common/process_utils.h"
#include "syzygy/kasko/api/crash_key.h"

// http://blogs.msdn.com/oldnewthing/archive/2004/10/25/247180.aspx
extern "C" IMAGE_DOS_HEADER __ImageBase;

namespace kasko {
namespace api {
namespace internal {

namespace {

// Used to store the CrashKey array address and size in the client process.
struct CrashKeyStorage {
  const CrashKey* crash_keys;
  size_t crash_key_count;
} g_crash_key_storage = {nullptr, 0};

// Returns the image path of |module| in |process|.
base::string16 GetModulePath(HANDLE process, HMODULE module) {
  base::char16 path_buffer[MAX_PATH];
  DWORD bytes_read = ::GetModuleFileNameEx(process, module, path_buffer,
                                           arraysize(path_buffer));
  if (bytes_read == 0)
    DPLOG(ERROR) << "GetModuleFileNameEx";
  else if (bytes_read >= arraysize(path_buffer))
    return base::string16();

  return path_buffer;
}

// Returns the image path of the current module.
base::string16 GetCurrentModulePath() {
  return GetModulePath(base::GetCurrentProcessHandle(),
                       reinterpret_cast<HMODULE>(&__ImageBase));
}

// Returns the linker timestamp of the current module.
DWORD GetCurrentModuleTimestamp() {
  uintptr_t image_dos_header_address =
      reinterpret_cast<uintptr_t>(&__ImageBase);
  IMAGE_DOS_HEADER* image_dos_header =
      reinterpret_cast<IMAGE_DOS_HEADER*>(image_dos_header_address);
  IMAGE_NT_HEADERS* image_nt_header = reinterpret_cast<IMAGE_NT_HEADERS*>(
      image_dos_header_address + image_dos_header->e_lfanew);
  return image_nt_header->FileHeader.TimeDateStamp;
}

// Returns the size of |module| in |process|.
DWORD GetModuleSize(HANDLE process, HMODULE module) {
  MODULEINFO module_info = {0};
  if (!::GetModuleInformation(process, module, &module_info,
                              sizeof(module_info))) {
    DPLOG(ERROR) << "GetModuleInformation";
    return 0;
  }
  DCHECK_NE(0u, module_info.SizeOfImage);
  return module_info.SizeOfImage;
}

// Returns the size of the current module.
DWORD GetCurrentModuleSize() {
  return GetModuleSize(base::GetCurrentProcessHandle(),
                       reinterpret_cast<HMODULE>(&__ImageBase));
}

// Reads a value of type T from |address| in |process| into |value|. Returns
// true if successful.
template <typename T>
bool ReadValueFromOtherProcess(HANDLE process, uintptr_t address, T* value) {
  DWORD bytes_count = 0;
  if (!::ReadProcessMemory(process, reinterpret_cast<void*>(address), value,
                           sizeof(T), &bytes_count)) {
    DPLOG(ERROR) << "ReadProcessMemory";
    return false;
  }
  if (bytes_count != sizeof(T))
    return false;
  return true;
}

// Reads the crash keys from another instance of the current module image,
// loaded into another process.
bool ReadCrashKeysFromProcessModule(HANDLE process,
                                    HMODULE module,
                                    std::vector<CrashKey>* crash_keys) {
  // Calculate the offset of g_crash_key_storage from our base address. It will
  // be the same in the other instance.
  ptrdiff_t storage_offset = reinterpret_cast<uintptr_t>(&g_crash_key_storage) -
                             reinterpret_cast<uintptr_t>(&__ImageBase);

  // Calculate the virtual address of g_crash_key_storage in the other instance.
  uintptr_t storage_address =
      storage_offset + reinterpret_cast<uintptr_t>(module);

  // Read the CrashKeyStorage structure, which contains the address and size of
  // a CrashKey array in the other process.
  CrashKeyStorage crash_key_storage = {0};
  if (!ReadValueFromOtherProcess(process, storage_address, &crash_key_storage))
    return false;

  // Prepare a buffer and read the CrashKey array into it.
  crash_keys->resize(crash_key_storage.crash_key_count);
  DWORD bytes_count = 0;
  if (!::ReadProcessMemory(
          process, crash_key_storage.crash_keys, crash_keys->data(),
          sizeof(CrashKey) * crash_keys->size(), &bytes_count)) {
    DPLOG(ERROR) << "ReadProcessMemory";
    crash_keys->clear();
    return false;
  }
  if (bytes_count != sizeof(CrashKey) * crash_keys->size()) {
    crash_keys->clear();
    return false;
  }

  // Validate the CrashKey array that we read. If any of the names or values is
  // not properly terminated, fail the entire operation.
  for (const auto& crash_key : *crash_keys) {
    if (::wcsnlen(crash_key.name, CrashKey::kNameMaxLength) ==
        CrashKey::kNameMaxLength) {
      crash_keys->clear();
      return false;
    }
    if (::wcsnlen(crash_key.value, CrashKey::kValueMaxLength) ==
        CrashKey::kValueMaxLength) {
      crash_keys->clear();
      return false;
    }
  }
  return true;
}

// Retrieves the linker timestamp from a module loaded into another process.
DWORD GetOtherModuleTimestamp(HANDLE process, HANDLE module) {
  // Read the relative address of the NT_IMAGE_HEADERS structure from the
  // IMAGE_DOS_HEADER (which is located at the module's base address).
  decltype(IMAGE_DOS_HEADER::e_lfanew) nt_header_offset = 0;
  if (!ReadValueFromOtherProcess(process,
                                 reinterpret_cast<uintptr_t>(module) +
                                     offsetof(IMAGE_DOS_HEADER, e_lfanew),
                                 &nt_header_offset)) {
    return 0;
  }
  if (nt_header_offset == 0)
    return 0;

  // Calculate the address of the timestamp, which is stored in
  // image_nt_header.FileHeader.TimeDateStamp.
  uintptr_t image_nt_header_address =
      reinterpret_cast<uintptr_t>(module) + nt_header_offset;
  uintptr_t image_file_header_address =
      image_nt_header_address + offsetof(IMAGE_NT_HEADERS, FileHeader);
  uintptr_t time_date_stamp_address =
      image_file_header_address + offsetof(IMAGE_FILE_HEADER, TimeDateStamp);

  // Read the value of the timestamp.
  decltype(IMAGE_FILE_HEADER::TimeDateStamp) time_date_stamp = 0;
  if (!ReadValueFromOtherProcess(process, time_date_stamp_address,
                                 &time_date_stamp)) {
    return 0;
  }

  return time_date_stamp;
}

// Reads a fingerprint of the current module, and provides a method to compare
// that fingerprint to a module in another process.
class CurrentModuleMatcher {
 public:
  CurrentModuleMatcher()
      : path_(GetCurrentModulePath()),
        timestamp_(GetCurrentModuleTimestamp()),
        size_(GetCurrentModuleSize()) {}

  // Returns true if the specifed |module| in |process| appears to be the same
  // image as the current module.
  bool Matches(HANDLE process, HMODULE module) {
    // Give up now if we failed to read any of our own identifying values. As a
    // result, we know we will fail later if we fail to read one of the other
    // module's values.
    if (path_.empty() || timestamp_ == 0 || size_ == 0)
      return false;

    base::string16 other_path = GetModulePath(process, module);
    if (other_path != path_)
      return false;

    DWORD other_size = GetModuleSize(process, module);
    if (other_size != size_)
      return false;

    DWORD other_timestamp = GetOtherModuleTimestamp(process, module);
    if (other_timestamp != timestamp_)
      return false;

    return true;
  }

 private:
  base::string16 path_;
  DWORD timestamp_;
  DWORD size_;
};

}  // namespace

void RegisterCrashKeys(const CrashKey* crash_keys, size_t count) {
  DCHECK(!g_crash_key_storage.crash_keys);
  g_crash_key_storage.crash_keys = crash_keys;
  DCHECK_EQ(0u, g_crash_key_storage.crash_key_count);
  g_crash_key_storage.crash_key_count = count;
}

bool ReadCrashKeysFromProcess(HANDLE process,
                              std::vector<CrashKey>* crash_keys) {
  ::common::ModuleVector modules;
  ::common::GetProcessModules(process, &modules);

  CurrentModuleMatcher module_matcher;

  for (const auto& module : modules) {
    if (module_matcher.Matches(process, module))
      return ReadCrashKeysFromProcessModule(process, module, crash_keys);
  }
  return false;
}

}  // namespace internal
}  // namespace api
}  // namespace kasko

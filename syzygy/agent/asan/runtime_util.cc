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

#include "syzygy/agent/asan/runtime_util.h"

#include <windows.h>  // NOLINT
#include <psapi.h>

#include "base/command_line.h"
#include "base/files/file_path.h"
#include "base/win/pe_image.h"
#include "syzygy/agent/asan/rtl_impl.h"
#include "syzygy/agent/asan/runtime.h"
#include "syzygy/common/asan_parameters.h"
#include "syzygy/common/com_utils.h"
#include "syzygy/common/logging.h"

// The linker satisfies this symbol. This gets us a pointer to our own module
// when we're loaded.
extern "C" IMAGE_DOS_HEADER __ImageBase;

namespace agent {
namespace asan {

namespace {

// Returns the name of this module.
bool GetSelfPath(base::FilePath* self_path) {
  DCHECK_NE(static_cast<base::FilePath*>(nullptr), self_path);

  HMODULE self = reinterpret_cast<HMODULE>(&__ImageBase);

  std::vector<wchar_t> name(1024, 0);
  while (true) {
    size_t n = ::GetModuleFileNameW(self, name.data(),
                                    static_cast<DWORD>(name.size()));
    if (n == 0) {
      DWORD error = ::GetLastError();
      LOG(ERROR) << "GetModuleFileNameW failed: "
                 << ::common::LogWe(error) << ".";
      return false;
    }

    // If we read the whole thing we're done.
    if (n < name.size())
      break;

    // Otherwise resize the buffer and try again.
    name.resize(2 * name.size(), 0);
  }

  *self_path = base::FilePath(name.data());
  return true;
}

// Used as user data by EnumImportChunksCallback. This is used to look for a
// module matching |basename|. Success or failure is returned via |match|.
struct EnumImportChunksCookie {
  const std::string* basename;
  bool match;
};

// Examines the imported |module|. If it matches the |basename| specified in
// |cookie|, then aborts the search and indicates success via the |match|
// parameter in |cookie|.
bool EnumImportChunksCallback(const base::win::PEImage& image,
                              LPCSTR module,
                              PIMAGE_THUNK_DATA name_table,
                              PIMAGE_THUNK_DATA iat,
                              PVOID cookie) {
  DCHECK_NE(static_cast<LPCSTR>(nullptr), module);
  DCHECK_NE(static_cast<PVOID>(nullptr), cookie);

  EnumImportChunksCookie* eicc =
      reinterpret_cast<EnumImportChunksCookie*>(cookie);
  if (::_stricmp(eicc->basename->c_str(), module) == 0) {
    // Indicate that the module was found.
    eicc->match = true;
    // Stop the enumeration as we're done.
    return false;
  }

  // Continue the iteration.
  return true;
}

// Inspects the given module for embedded Asan parameters. If they are found
// sets a pointer to them in |asan_params|. Returns true on success, false
// otherwise.
bool InspectModuleForEmbeddedAsanParameters(
    const std::string& self_basename,
    HMODULE module,
    const ::common::AsanParameters** asan_params) {
  DCHECK_NE(static_cast<HMODULE>(nullptr), module);
  DCHECK_NE(static_cast<::common::AsanParameters**>(nullptr), asan_params);

  *asan_params = nullptr;

  base::win::PEImage pe_image(module);
  EnumImportChunksCookie eicc = { &self_basename, false };
  pe_image.EnumImportChunks(&EnumImportChunksCallback, &eicc);

  // If there was no matching import then we can skip this module.
  if (!eicc.match)
    return true;

  // Look for the magic section containing the runtime parameters. If found
  // then set the pointer to the parameters.
  PIMAGE_SECTION_HEADER section = pe_image.GetImageSectionHeaderByName(
      ::common::kAsanParametersSectionName);
  if (section != nullptr) {
    const uint8_t* image_base = reinterpret_cast<const uint8_t*>(module);
    *asan_params = reinterpret_cast<const ::common::AsanParameters*>(
        image_base + section->VirtualAddress);
  }

  return true;
}

// |asan_params| will be populated with a pointer to any found Asan parameters,
// and will be set to nullptr if none are found.
bool LookForEmbeddedAsanParameters(
    const ::common::AsanParameters** asan_params) {
  DCHECK_NE(static_cast<::common::AsanParameters**>(nullptr), asan_params);
  *asan_params = nullptr;

  // Get the path of this module.
  base::FilePath self_path;
  if (!GetSelfPath(&self_path))
    return false;

  // Get the base name of this module. We'll be looking for modules that import
  // it.
  std::string self_basename = self_path.BaseName().AsUTF8Unsafe();

  // Determine how much space we need for the module list.
  HANDLE process = ::GetCurrentProcess();
  DWORD bytes_needed = 0;
  if (!::EnumProcessModules(process, nullptr, 0, &bytes_needed)) {
    DWORD error = ::GetLastError();
    LOG(ERROR) << "EnumProcessModules failed: "
               << ::common::LogWe(error) << ".";
    return false;
  }

  // Get the list of module handles.
  std::vector<HMODULE> modules(bytes_needed / sizeof(HMODULE));
  if (!::EnumProcessModules(process, modules.data(), bytes_needed,
                            &bytes_needed)) {
    DWORD error = ::GetLastError();
    LOG(ERROR) << "EnumProcessModules failed: "
               << ::common::LogWe(error) << ".";
    return false;
  }

  // Inspect each module to see if it contains Asan runtime parameters. The
  // first ones found will be used.
  for (size_t i = 0; i < modules.size(); ++i) {
    if (!InspectModuleForEmbeddedAsanParameters(
             self_basename, modules[i], asan_params)) {
      return false;
    }

    // If this module contained parameters then we've finished our search.
    if (*asan_params != nullptr)
      return true;
  }

  return true;
}

}  // namespace

bool SetUpAsanRuntime(AsanRuntime** asan_runtime) {
  DCHECK_NE(static_cast<AsanRuntime**>(nullptr), asan_runtime);
  DCHECK_EQ(static_cast<AsanRuntime*>(nullptr), *asan_runtime);

  // Look for any parameters that have been embedded in instrumented modules.
  const ::common::AsanParameters* asan_params = nullptr;
  if (!LookForEmbeddedAsanParameters(&asan_params )) {
    LOG(ERROR) << "Error while trying to find embedded Asan parameters.";
  }

  std::unique_ptr<AsanRuntime> runtime(new AsanRuntime());
  if (runtime.get() == nullptr)
    return false;

  // Inflate these and inject them into the runtime library. These will serve
  // as the baseline parameters that will then be potentially modified by any
  // parameters via the environment.
  if (asan_params != nullptr &&
      !::common::InflateAsanParameters(asan_params,
                                       &runtime->params())) {
    LOG(ERROR) << "Failed to inflate embedded Asan parameters.";
  }

  // Get the flags string from the environment.
  std::wstring asan_flags_str;
  if (!AsanRuntime::GetAsanFlagsEnvVar(&asan_flags_str)) {
    LOG(ERROR) << "Error while trying to read Asan command line.";
  }

  // Setup the runtime library with the given options.
  if (!runtime->SetUp(asan_flags_str))
    return false;
  agent::asan::SetUpRtl(runtime.get());

  // Transfer ownership to the caller.
  *asan_runtime = runtime.release();
  return true;
}

void TearDownAsanRuntime(AsanRuntime** asan_runtime) {
  DCHECK_NE(static_cast<AsanRuntime**>(nullptr), asan_runtime);
  if (asan_runtime == nullptr)
    return;
  agent::asan::TearDownRtl();
  (*asan_runtime)->TearDown();
  delete *asan_runtime;
  *asan_runtime = nullptr;
}

}  // namespace asan
}  // namespace agent

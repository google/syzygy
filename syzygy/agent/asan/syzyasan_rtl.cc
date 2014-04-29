// Copyright 2012 Google Inc. All Rights Reserved.
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

#include <windows.h>  // NOLINT
#include <psapi.h>

#include "base/at_exit.h"
#include "base/atomicops.h"
#include "base/command_line.h"
#include "base/logging.h"
#include "base/files/file_path.h"
#include "base/win/pe_image.h"
#include "syzygy/agent/asan/asan_rtl_impl.h"
#include "syzygy/agent/asan/asan_runtime.h"
#include "syzygy/agent/common/agent.h"
#include "syzygy/common/com_utils.h"
#include "syzygy/common/logging.h"

// The linker satisfies this symbol. This gets us a pointer to our own module
// when we're loaded.
extern "C" IMAGE_DOS_HEADER __ImageBase;

namespace {

using agent::asan::AsanRuntime;

// Our AtExit manager required by base.
base::AtExitManager* at_exit = NULL;

// The asan runtime manager.
AsanRuntime* asan_runtime = NULL;

void SetUpAtExitManager() {
  DCHECK(at_exit == NULL);
  at_exit = new base::AtExitManager();
  CHECK(at_exit != NULL);
}

void TearDownAtExitManager() {
  DCHECK(at_exit != NULL);
  delete at_exit;
  at_exit = NULL;
}

// Returns the name of this module.
bool GetSelfPath(base::FilePath* self_path) {
  DCHECK_NE(reinterpret_cast<base::FilePath*>(NULL), self_path);

  HMODULE self = reinterpret_cast<HMODULE>(&__ImageBase);

  std::vector<wchar_t> name(1024, 0);
  while (true) {
    size_t n = ::GetModuleFileNameW(self, name.data(), name.size());
    if (n == 0) {
      DWORD error = ::GetLastError();
      LOG(ERROR) << "GetModuleFileNameW failed: "
                 << common::LogWe(error) << ".";
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
  DCHECK_NE(reinterpret_cast<LPCSTR>(NULL), module);
  DCHECK_NE(reinterpret_cast<PVOID>(NULL), cookie);

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

// Inspects the given module for embedded ASAN parameters. If they are found
// sets a pointer to them in |asan_params|. Returns true on success, false
// otherwise.
bool InspectModuleForEmbeddedAsanParameters(
    const std::string& self_basename,
    HMODULE module,
    const common::AsanParameters** asan_params) {
  DCHECK_NE(reinterpret_cast<HMODULE>(NULL), module);
  DCHECK_NE(reinterpret_cast<common::AsanParameters**>(NULL), asan_params);

  *asan_params = NULL;

  base::win::PEImage pe_image(module);
  EnumImportChunksCookie eicc = { &self_basename, false };
  pe_image.EnumImportChunks(&EnumImportChunksCallback, &eicc);

  // If there was no matching import then we can skip this module.
  if (!eicc.match)
    return true;

  // Look for the magic section containing the runtime parameters. If found
  // then set the pointer to the parameters.
  PIMAGE_SECTION_HEADER section = pe_image.GetImageSectionHeaderByName(
      common::kAsanParametersSectionName);
  if (section != NULL) {
    const uint8* image_base = reinterpret_cast<const uint8*>(module);
    *asan_params = reinterpret_cast<const common::AsanParameters*>(
        image_base + section->VirtualAddress);
  }

  return true;
}

// |asan_params| will be populated with a pointer to any found ASAN parameters,
// and will be set to NULL if none are found.
bool LookForEmbeddedAsanParameters(const common::AsanParameters** asan_params) {
  DCHECK_NE(reinterpret_cast<common::AsanParameters**>(NULL), asan_params);
  *asan_params = NULL;

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
  if (!::EnumProcessModules(process, NULL, 0, &bytes_needed)) {
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

  // Inspect each module to see if it contains ASAN runtime parameters. The
  // first ones found will be used.
  for (size_t i = 0; i < modules.size(); ++i) {
    if (!InspectModuleForEmbeddedAsanParameters(
             self_basename, modules[i], asan_params)) {
      return false;
    }

    // If this module contained parameters then we've finished our search.
    if (*asan_params != NULL)
      return true;
  }

  return true;
}

void SetUpAsanRuntime() {
  DCHECK(asan_runtime == NULL);
  asan_runtime = new AsanRuntime();
  CHECK(asan_runtime != NULL);

  // Look for any parameters that have been embedded in instrumented modules.
  const common::AsanParameters* asan_params = NULL;
  if (!LookForEmbeddedAsanParameters(&asan_params )) {
    LOG(ERROR) << "Error while trying to find embedded Asan parameters.";
  }

  // Inflate these and inject them into the runtime library. These will serve
  // as the baseline parameters that will then be potentially modified by any
  // parameters via the environment.
  if (asan_params != NULL &&
      !common::InflateAsanParameters(asan_params, &asan_runtime->params())) {
    LOG(ERROR) << "Failed to inflate embedded Asan parameters.";
  }

  // Get the flags string from the environment.
  std::wstring asan_flags_str;
  if (!AsanRuntime::GetAsanFlagsEnvVar(&asan_flags_str)) {
    LOG(ERROR) << "Error while trying to read Asan command line.";
  }

  // Setup the runtime library with the given options.
  asan_runtime->SetUp(asan_flags_str);
  agent::asan::SetUpRtl(asan_runtime);
}

void TearDownAsanRuntime() {
  DCHECK(asan_runtime != NULL);
  asan_runtime->TearDown();
  delete asan_runtime;
  asan_runtime = NULL;
}

}  // namespace

extern "C" {

BOOL WINAPI DllMain(HMODULE instance, DWORD reason, LPVOID reserved) {
  agent::common::InitializeCrt();

  switch (reason) {
    case DLL_PROCESS_ATTACH:
      // Create the At-Exit manager.
      SetUpAtExitManager();

      // Disable logging. In the case of Chrome this is running in a sandboxed
      // process where logging to file doesn't help us any. In other cases the
      // log output will still go to console.
      CommandLine::Init(0, NULL);
      common::InitLoggingForDll(L"asan");

      SetUpAsanRuntime();

      break;

    case DLL_THREAD_ATTACH:
      // Nothing to do here.
      break;

    case DLL_THREAD_DETACH:
      // Nothing to do here.
      break;

    case DLL_PROCESS_DETACH:
      CommandLine::Reset();
      // This should be the last thing called in the agent DLL before it
      // gets unloaded. Everything should otherwise have been initialized
      // and we're now just cleaning it up again.
      agent::asan::TearDownRtl();
      TearDownAsanRuntime();
      break;

    default:
      NOTREACHED();
      break;
  }

  return TRUE;
}

}  // extern "C"

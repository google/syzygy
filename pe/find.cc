// Copyright 2011 Google Inc.
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
// Implementation of utility functions for module/PDB search and discovery.
// Leverages the debughlp back-end so that behaviour is consistent with those
// tools.

#include "syzygy/pe/find.h"

#include <dbghelp.h>
#include <winnt.h>
#include "base/environment.h"
#include "base/file_util.h"
#include "base/logging.h"
#include "base/string_split.h"
#include "base/utf_string_conversions.h"
#include "sawbuck/common/com_utils.h"
#include "syzygy/pdb/pdb_util.h"
#include "syzygy/pe/pdb_info.h"
#include "syzygy/pe/pe_data.h"
#include "syzygy/pe/pe_file.h"

namespace pe {

namespace {

bool GetEnvVar(const char* name, std::wstring* value) {
  DCHECK(value != NULL);
  value->clear();

  scoped_ptr<base::Environment> env(base::Environment::Create());
  if (env.get() == NULL) {
    LOG(ERROR) << "base::Environment::Create returned NULL.";
    return false;
  }

  // If this fails, the environment variable simply does not exist.
  std::string var;
  if (!env->GetVar(name, &var))
    return true;

  if (!UTF8ToWide(var.c_str(),
                  var.size(),
                  value)) {
    LOG(ERROR) << "UTF8ToWide(\"" << var << "\" failed.";
    return false;
  }

  return true;
}

bool FindFile(const FilePath& file_path,
              const wchar_t* search_paths,
              const void* id,
              uint32 data,
              uint32 flags,
              FilePath* found_file) {
  DCHECK(found_file != NULL);

  found_file->clear();

  HANDLE handle = ::GetCurrentProcess();

  BOOL result = ::SymInitialize(handle, NULL, FALSE);
  if (result == FALSE) {
    LOG(ERROR) << "SymInitialize failed: " << com::LogWe();
    return false;
  }

  std::wstring dir = file_path.DirName().value();
  std::wstring basename = file_path.BaseName().value();

  // Augment the search paths with the directory of file_path and the
  // current working directory.
  std::wstring paths = dir;
  paths.append(L";.;");
  paths.append(search_paths);

  // Search for the file.
  wchar_t buffer[MAX_PATH];
  result = ::SymFindFileInPathW(handle,
                                paths.c_str(),
                                basename.c_str(),
                                const_cast<void*>(id),
                                data,
                                0,
                                flags,
                                &buffer[0],
                                NULL,
                                NULL);
  if (::SymCleanup(handle) == FALSE) {
    LOG(ERROR) << "SymCleanup failed: " << com::LogWe();
    return false;
  }
  if (!result) {
    // If there is a zero error code, this simply means that the search failed
    // to find anything, which is not an error.
    if (::GetLastError() == 0)
      return true;

    LOG(ERROR) << "SymFindFileInPath(\"" << file_path.value() << "\") failed: "
               << com::LogWe();
    return false;
  }

  *found_file = FilePath(buffer);

  return true;
}

}  // namespace

bool FindModuleBySignature(const pe::PEFile::Signature& module_signature,
                           const wchar_t* search_paths,
                           FilePath* module_path) {
  DCHECK(module_path != NULL);

  FilePath path(module_signature.path);
  const void* id =
      reinterpret_cast<void*>(module_signature.module_time_date_stamp);
  return FindFile(path,
                  search_paths,
                  id,
                  module_signature.module_size,
                  SSRVOPT_DWORD,
                  module_path);
}

bool FindModuleBySignature(const pe::PEFile::Signature& module_signature,
                           FilePath* module_path) {
  DCHECK(module_path != NULL);

  std::wstring search_paths;
  if (!GetEnvVar("PATH", &search_paths))
    return false;

  return FindModuleBySignature(module_signature,
                               search_paths.c_str(),
                               module_path);
}

bool FindPdbForModule(const FilePath& module_path,
                      const wchar_t* search_paths,
                      FilePath* pdb_path) {
  DCHECK(pdb_path != NULL);

  PdbInfo pdb_info;
  if (!pdb_info.Init(module_path))
    return false;

  return FindFile(pdb_info.pdb_file_name(),
                  search_paths,
                  &pdb_info.signature(),
                  pdb_info.pdb_age(),
                  SSRVOPT_GUIDPTR,
                  pdb_path);
}

bool FindPdbForModule(const FilePath& module_path,
                      FilePath* pdb_path) {
  DCHECK(pdb_path != NULL);

  std::wstring search_paths;
  if (!GetEnvVar("_NT_SYMBOL_PATH", &search_paths))
    return false;

  return FindPdbForModule(module_path,
                          search_paths.c_str(),
                          pdb_path);
}

}  // namespace pe

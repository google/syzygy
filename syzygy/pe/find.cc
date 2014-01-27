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
//
// Implementation of utility functions for module/PDB search and discovery.
// Leverages the debughlp back-end so that behaviour is consistent with those
// tools.

#include "syzygy/pe/find.h"

#include "base/environment.h"
#include "base/file_util.h"
#include "base/logging.h"
#include "base/utf_string_conversions.h"
#include "base/strings/string_split.h"
#include "syzygy/common/com_utils.h"
#include "syzygy/common/dbghelp_util.h"
#include "syzygy/pdb/pdb_util.h"
#include "syzygy/pe/pdb_info.h"
#include "syzygy/pe/pe_data.h"
#include "syzygy/pe/pe_file.h"

namespace pe {

namespace {

bool GetEnvVar(const char* name, std::wstring* value) {
  DCHECK(name != NULL);
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

// Return TRUE to continue searching, FALSE if we want the search to stop.
BOOL CALLBACK FindPdbFileCallback(PCTSTR path, PVOID context) {
  DCHECK(path != NULL);
  DCHECK(context != NULL);

  base::FilePath pdb_path(path);
  const PdbInfo* pdb_info = static_cast<PdbInfo*>(context);

  pdb::PdbInfoHeader70 pdb_header;
  if (!pdb::ReadPdbHeader(pdb_path, &pdb_header))
    return TRUE;
  if (!pdb_info->IsConsistent(pdb_header))
    return TRUE;

  return FALSE;
}

// Return TRUE to continue searching, FALSE if we want the search to stop.
BOOL CALLBACK FindPeFileCallback(PCTSTR path, PVOID context) {
  DCHECK(path != NULL);
  DCHECK(context != NULL);

  base::FilePath pe_path(path);
  const PEFile::Signature* pe_info = static_cast<PEFile::Signature*>(context);

  PEFile pe_file;
  if (!pe_file.Init(pe_path))
    return TRUE;
  PEFile::Signature pe_sig;
  pe_file.GetSignature(&pe_sig);

  // We don't care about the base address or the path.
  if (pe_sig.module_checksum != pe_info->module_checksum ||
      pe_sig.module_size != pe_info->module_size ||
      pe_sig.module_time_date_stamp != pe_info->module_time_date_stamp) {
    return TRUE;
  }

  return FALSE;
}

bool FindFile(const base::FilePath& file_path,
              const base::StringPiece16& search_paths,
              const void* id,
              uint32 data,
              uint32 flags,
              PFINDFILEINPATHCALLBACKW callback,
              void* callback_context,
              base::FilePath* found_file) {
  DCHECK(found_file != NULL);

  found_file->clear();

  HANDLE handle = ::GetCurrentProcess();

  if (!common::SymInitialize(handle, NULL, false))
    return false;

  base::FilePath dir = file_path.DirName();
  std::wstring basename = file_path.BaseName().value();

  // Augment the search paths with the directory of file_path and the
  // current working directory.
  std::wstring paths;
  if (file_util::PathExists(dir)) {
    paths.append(dir.value());
    paths.push_back(L';');
  }
  paths.append(L".;");
  paths.append(search_paths.begin(), search_paths.end());

  // Search for the file.
  wchar_t buffer[MAX_PATH];
  BOOL result = ::SymFindFileInPathW(handle,
                                     paths.c_str(),
                                     basename.c_str(),
                                     const_cast<void*>(id),
                                     data,
                                     0,
                                     flags,
                                     &buffer[0],
                                     callback,
                                     callback_context);
  if (::SymCleanup(handle) == FALSE) {
    DWORD error = ::GetLastError();
    LOG(ERROR) << "SymCleanup failed: " << common::LogWe(error);
    return false;
  }
  if (!result) {
    // If there is a zero error code, this simply means that the search failed
    // to find anything, which is not an error.
    DWORD error = ::GetLastError();
    if (error == 0)
      return true;

    LOG(ERROR) << "SymFindFileInPath(\"" << file_path.value() << "\") failed: "
               << common::LogWe(error);
    return false;
  }

  *found_file = base::FilePath(buffer);

  return true;
}

}  // namespace

bool PeAndPdbAreMatched(const base::FilePath& pe_path,
                        const base::FilePath& pdb_path) {
  pe::PdbInfo pe_pdb_info;
  if (!pe_pdb_info.Init(pe_path))
    return false;
  pdb::PdbInfoHeader70 pdb_info;
  if (!pdb::ReadPdbHeader(pdb_path, &pdb_info))
    return false;
  if (!pe_pdb_info.IsConsistent(pdb_info))
    return false;
  return true;
}

bool FindModuleBySignature(const PEFile::Signature& module_signature,
                           const base::StringPiece16& search_paths,
                           base::FilePath* module_path) {
  DCHECK(module_path != NULL);

  std::vector<base::FilePath> candidate_paths;
  if (!module_path->empty())
    candidate_paths.push_back(*module_path);
  candidate_paths.push_back(base::FilePath(module_signature.path));

  const void* id =
      reinterpret_cast<void*>(module_signature.module_time_date_stamp);

  // Try a search based on each of the candidate paths.
  for (size_t i = 0; i < candidate_paths.size(); ++i) {
    const base::FilePath& path = candidate_paths[i];

    if (!FindFile(path,
                  search_paths,
                  id,
                  module_signature.module_size,
                  SSRVOPT_DWORD,
                  FindPeFileCallback,
                  const_cast<PEFile::Signature*>(&module_signature),
                  module_path)) {
      return false;
    }

    // If the search was successful we can terminate early.
    if (!module_path->empty())
      return true;
  }
  DCHECK(module_path->empty());

  return true;
}

bool FindModuleBySignature(const PEFile::Signature& module_signature,
                           base::FilePath* module_path) {
  DCHECK(module_path != NULL);

  std::wstring search_paths;
  if (!GetEnvVar("PATH", &search_paths))
    return false;

  return FindModuleBySignature(module_signature,
                               search_paths.c_str(),
                               module_path);
}

bool FindPdbForModule(const base::FilePath& module_path,
                      const base::StringPiece16& search_paths,
                      base::FilePath* pdb_path) {
  DCHECK(pdb_path != NULL);

  std::vector<base::FilePath> candidate_paths;
  if (!pdb_path->empty())
    candidate_paths.push_back(*pdb_path);

  PdbInfo pdb_info;
  if (!pdb_info.Init(module_path))
    return false;
  candidate_paths.push_back(pdb_info.pdb_file_name());

  // Prepend the module path to the symbol path.
  std::wstring search_path(module_path.DirName().value());
  search_path.append(L";");
  search_path.append(search_paths.begin(), search_paths.end());

  for (size_t i = 0; i < candidate_paths.size(); ++i) {
    const base::FilePath& path = candidate_paths[i];

    if (!FindFile(path,
                  search_path.c_str(),
                  &pdb_info.signature(),
                  pdb_info.pdb_age(),
                  SSRVOPT_GUIDPTR,
                  FindPdbFileCallback,
                  &pdb_info,
                  pdb_path)) {
      return false;
    }

    // If the search was successful we can terminate early.
    if (!pdb_path->empty())
      return true;
  }
  DCHECK(pdb_path->empty());

  return true;
}

bool FindPdbForModule(const base::FilePath& module_path,
                      base::FilePath* pdb_path) {
  DCHECK(pdb_path != NULL);

  std::wstring search_paths;
  if (!GetEnvVar("_NT_SYMBOL_PATH", &search_paths))
    return false;

  return FindPdbForModule(module_path,
                          search_paths.c_str(),
                          pdb_path);
}

}  // namespace pe

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
// Declares utility functions for finding a module and a PDB file corresponding
// to the given module signature.

#ifndef SYZYGY_PE_FIND_H_
#define SYZYGY_PE_FIND_H_

#include "base/file_path.h"
#include "syzygy/pe/pe_file.h"

namespace pe {

// Looks for the module matching a given module signature. Uses the module
// signature path as the starting point of the search.
//
// Given an example module path of "C:\foo\foo.dll", the search strategy
// is as follows:
//
// 1. Looks for "C:\foo\foo.dll".
// 2. Looks for "foo.dll" in the current working directory.
// 3. Looks for "foo.dll" in each directory in @p search_paths.
//
// @param module_signature The signature of the module we are searching for.
//     This also contains the path to the module from which the signature was
//     originally taken, and this is used as the starting point of the search.
// @param search_paths A semi-colon separated list of additional search paths.
// @param module_path If the module is successfully found, this will contain
//     the absolute path to the discovered module.
//
// @returns false if any errors occur, true otherwise. If the module is found
//     its path is returned in @p module_path.
bool FindModuleBySignature(const pe::PEFile::Signature& module_signature,
                           const wchar_t* search_paths,
                           FilePath* module_path);

// Same as 3-parameter FindModuleBySignature, but uses the PATH environment
// variable as the list of search paths.
bool FindModuleBySignature(const pe::PEFile::Signature& module_signature,
                           FilePath* module_path);

// Searches for the PDB file corresponding to the given module. Uses the
// path stored in the module's debug information as a starting point, and also
// searches in the current working directory.
//
// Given an example PDB starting path of "C:\foo\foo.pdb", the search strategy
// is as follows:
//
// 1. Looks for "C:\foo\foo.pdb".
// 2. Looks for "foo.pdb" in the current working directory.
// 3. Looks for "foo.pdb" in each directory in @p search_paths, or looks by
//    GUID/age in each symbol server listed in @p search_paths.
//
// @param module_path The module whose PDB file we are looking for.
// @param search_paths A semi-colon separated list of additional search paths.
//     May use the svr* and cache* notation of symbol servers.
// @param pdb_path If the PDB is successfully found, this will contain the
//     absolute path to it. If it is found on a symbol server, it will first
//     be downloaded and stored locally.
//
// @returns false if any errors occur, true otherwise. If the PDB file is found
//     its path is returned in @p pdb_path.
bool FindPdbForModule(const FilePath& module_path,
                      const wchar_t* search_paths,
                      FilePath* pdb_path);

// Same 3-parameter FindPdbForModule, but uses the _NT_SYMBOL_PATH environment
// variable as the list of search paths.
bool FindPdbForModule(const FilePath& module_path,
                      FilePath* pdb_path);

}  // namespace pe

#endif  // SYZYGY_PE_FIND_H_

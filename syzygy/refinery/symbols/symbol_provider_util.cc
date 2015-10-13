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

#include "syzygy/refinery/symbols/symbol_provider_util.h"

#include <string>

#include "base/environment.h"
#include "base/numerics/safe_conversions.h"
#include "base/strings/string16.h"
#include "base/strings/utf_string_conversions.h"
#include "syzygy/pe/find.h"
#include "syzygy/refinery/process_state/process_state.h"
#include "syzygy/refinery/process_state/process_state_util.h"

namespace refinery {

namespace {

// TODO(manzagop): this probably exists somewhere?
bool GetEnvVar(const char* name, base::string16* value) {
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

  if (!base::UTF8ToUTF16(var.c_str(), var.size(), value)) {
    LOG(ERROR) << "base::UTF8ToUTF16(\"" << var << "\" failed.";
    return false;
  }

  return true;
}

}  // namespace

bool GetModuleSignature(const Address va,
                        ProcessState* process_state,
                        pe::PEFile::Signature* signature) {
  DCHECK(process_state); DCHECK(signature);

  // Find the module record corresponding to the virtual address.
  ModuleRecordPtr module_record;
  if (!process_state->FindSingleRecord(va, &module_record))
    return false;

  const AddressRange& module_range = module_record->range();
  const Module& module = module_record->data();

  // Get the module's path.
  const std::string& module_path = module.name();
  base::string16 module_path_wide;
  if (!base::UTF8ToUTF16(module_path.c_str(), module_path.size(),
                         &module_path_wide)) {
    LOG(ERROR) << "base::UTF8ToUTF16(\"" << module_path << "\" failed.";
    return false;
  }

  // Get the module's address.
  if (!base::IsValueInRangeForNumericType<uint32>(module_range.start())) {
    LOG(ERROR) << "PE::Signature doesn't support 64bit addresses. Address: "
               << module_range.start();
    return false;
  }
  pe::PEFile::AbsoluteAddress module_address(
      base::checked_cast<uint32>(module_range.start()));

  signature->path = module_path_wide;
  signature->base_address = module_address;
  signature->module_size = module_range.size();
  signature->module_checksum = module.checksum();
  signature->module_time_date_stamp = module.timestamp();

  return true;
}

bool GetPdbPath(const pe::PEFile::Signature& signature,
                base::FilePath* pdb_path) {
  DCHECK(pdb_path);

  // Get the module's path.
  base::string16 symbol_paths;
  GetEnvVar("_NT_SYMBOL_PATH", &symbol_paths);
  base::FilePath module_local_path;
  if (!pe::FindModuleBySignature(signature, symbol_paths, &module_local_path) ||
      module_local_path.empty()) {
    LOG(ERROR) << "Failed to find module (name, size, timestamp): "
               << signature.path << ", " << signature.module_size << ", "
               << signature.module_time_date_stamp;
    return false;
  }

  // Get the pdb's path.
  if (!pe::FindPdbForModule(module_local_path, symbol_paths, pdb_path) ||
      pdb_path->empty()) {
    LOG(ERROR) << "Failed to find pdb for module " << signature.path;
    return false;
  }

  return true;
}

}  // namespace refinery

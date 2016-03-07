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

#ifndef SYZYGY_REFINERY_PROCESS_STATE_PROCESS_STATE_UTIL_H_
#define SYZYGY_REFINERY_PROCESS_STATE_PROCESS_STATE_UTIL_H_

#include <string>

#include "base/strings/string_piece.h"
#include "syzygy/refinery/core/address.h"
#include "syzygy/refinery/process_state/layer_data.h"
#include "syzygy/refinery/process_state/process_state.h"
#include "syzygy/refinery/process_state/refinery.pb.h"
#include "syzygy/refinery/types/type.h"

namespace refinery {

// A class for interacting with a ProcessState's module layer.
class ModuleLayerAccessor {
 public:
  explicit ModuleLayerAccessor(ProcessState* process_state);

  // Adds a module instance record to the process state. Also updates the module
  // layer's data if the instance is for a new module.
  // @note If the module is added to the layer's data, it is with a signature
  // that has a load address of 0, as we fold multiple module instances to a
  // single module identifier (and signature).
  // @param range the module instance's memory range.
  // @param checksum the module's checksum.
  // @param timestamp the module's timestamp.
  // @param path the module's path.
  void AddModuleRecord(const AddressRange& range,
                       const uint32_t checksum,
                       const uint32_t timestamp,
                       const std::wstring& path);

  // Retrieves the signature of the module instance containing @p va.
  // @note On success, the signature's base address is set to the module
  //     instance's actual load address.
  // @param va virtual address for which to get a module signature.
  // @param signature on success, the module signature.
  // @returns true on success, false on failure.
  bool GetModuleSignature(const Address va, pe::PEFile::Signature* signature);

  // Retrieves the signature of module @p id.
  // @note On success, the returned signature's base address is 0.
  // @param id module identifier for which to get a module signature.
  // @param signature on success, the module signature.
  // @returns true on success, false on failure.
  bool GetModuleSignature(const ModuleId id, pe::PEFile::Signature* signature);

  // Retrieves the module identifier corresponding to @p va.
  // @param virtual address for which to get a module identifier.
  // @returns the module identifier, or kNoModuleId if @p va does not correspond
  //     to a module.
  ModuleId GetModuleId(const Address va);

  // Retrieves the module identifier corresponding to @p signature.
  // @param signature for which to get a module identifier.
  // @returns the module identifier, or kNoModuleId if @p signature does not
  //     correspond to a module known to the process state.
  ModuleId GetModuleId(const pe::PEFile::Signature& signature);

 private:
  ProcessState* process_state_;  // Not owned, must outlive this class.
};

// Adds a typed block record to @p process_state.
// TODO(manzagop): avoid adding typed block duplicates. Longer term we may
// introduce more complex handling (eg notions of certainty).
bool AddTypedBlockRecord(const AddressRange& range,
                         base::StringPiece16 data_name,
                         ModuleId module_id,
                         TypeId type_id,
                         ProcessState* process_state);

}  // namespace refinery

#endif  // SYZYGY_REFINERY_PROCESS_STATE_PROCESS_STATE_UTIL_H_

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

#ifndef SYZYGY_REFINERY_PROCESS_STATE_LAYER_DATA_H_
#define SYZYGY_REFINERY_PROCESS_STATE_LAYER_DATA_H_

#include <vector>

#include "base/md5.h"
#include "base/containers/hash_tables.h"
#include "base/strings/string_piece.h"
#include "syzygy/pe/pe_file.h"

namespace refinery {

// Empty shell.
class NoData {
};

// An abstracted module identifier. This has a one-to-one mapping to platform
// specific module identifiers, eg {size, checksum, timstamp} on Windows. Note
// that multiple instances of the same module may be mapped at different
// addresses in a process state.
typedef uint32_t ModuleId;
const ModuleId kNoModuleId = static_cast<ModuleId>(-1);

struct PESignatureHasher {
 public:
  std::size_t operator()(pe::PEFile::Signature const& s) const;
};

// Data relevant to a process state's module layer.
class ModuleLayerData {
 public:
  using Signatures = std::vector<pe::PEFile::Signature>;

  ModuleLayerData();

  // Find the module id corresponding to a signature.
  // @param signature the module's signature.
  // @returns the corresponding module id, or kNoModuleId if the signature is
  //     unknown.
  ModuleId Find(const pe::PEFile::Signature& signature) const;

  // Find the module id corresponding to a signature if it exists, otherwise
  // index the signature and return the newly assigned module id.
  // @param signature the module's signature.
  // @returns the corresponding module id.
  ModuleId FindOrIndex(const pe::PEFile::Signature& signature);

  // Find and return the signature corresponding to a module @p id.
  // @param id the module identifier.
  // @param signature on success, contains the signature corresponding to module
  //     @p id.
  // @returns true on success, false otherwise.
  bool Find(ModuleId id, pe::PEFile::Signature* signature) const;

  const Signatures& signatures() const { return signatures_; }

 private:
  std::unordered_map<pe::PEFile::Signature, ModuleId, PESignatureHasher>
      signature_to_id_;
  Signatures signatures_;
};

}  // namespace refinery

#endif  // SYZYGY_REFINERY_PROCESS_STATE_LAYER_DATA_H_

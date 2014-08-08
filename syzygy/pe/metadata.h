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
// Declaration of a simple metadata class, which contains toolchain information
// which will be embedded in the outputs produced by the toolchain. Every
// output has one thing in common: it is has been produced from or with
// respect to a given module, and it has been produced by a fixed version of
// the toolchain.

#ifndef SYZYGY_PE_METADATA_H_
#define SYZYGY_PE_METADATA_H_

#include "base/values.h"
#include "base/time/time.h"
#include "syzygy/block_graph/block_graph.h"
#include "syzygy/common/syzygy_version.h"
#include "syzygy/core/serialization.h"
#include "syzygy/pe/pe_file.h"

// Forward declaration.
namespace core {
class JSONFileWriter;
}  // namespace core

namespace pe {

using base::Time;
using block_graph::BlockGraph;
using common::SyzygyVersion;

// Class encapsulating the metadata that is required for traceability and
// consistency at every step in the toolchain.
class Metadata {
 public:

  Metadata();

  // Initialize this metadata for a given module. Automatically infers
  // command-line, time, and toolchain version from the environment. Assumes
  // that the singleton CommandLine has already been initialized.
  bool Init(const PEFile::Signature& module_signature);

  // Confirms the metadata is consistent with the given module and current
  // toolchain version.
  bool IsConsistent(const PEFile::Signature& module_signature) const;

  // Functions for serialization to and from JSON.
  bool SaveToJSON(core::JSONFileWriter* json_file) const;
  bool LoadFromJSON(const base::DictionaryValue& metadata);

  // Functions for serialization to and from a block.
  bool SaveToBlock(BlockGraph::Block* block) const;
  bool LoadFromBlock(const BlockGraph::Block* block);

  // Functions for serialization to and from a PE file.
  bool LoadFromPE(const PEFile& pe_file);

  // Serialization functions.
  bool Save(core::OutArchive* out_archive) const;
  bool Load(core::InArchive* in_archive);

  // Comparison operators for serialization testing.
  // @{
  bool operator==(const Metadata& rhs) const;
  bool operator!=(const Metadata& rhs) const { return !operator==(rhs); }
  // @}

  // Accessors.
  const std::string& command_line() const { return command_line_; }
  Time creation_time() const { return creation_time_; }
  const SyzygyVersion& toolchain_version() const { return toolchain_version_; }
  const PEFile::Signature& module_signature() const {
    return module_signature_;
  }

  // Mutators. These are mainly for explicit testing.
  void set_command_line(const std::string& command_line) {
    command_line_ = command_line;
  }
  void set_creation_time(const Time& creation_time) {
    creation_time_ = creation_time;
  }
  void set_toolchain_version(const SyzygyVersion& toolchain_version) {
    toolchain_version_ = toolchain_version;
  }
  void set_module_signature(const PEFile::Signature& module_signature) {
    module_signature_ = module_signature;
  }

 private:
  // The command-line that was used to produce the output.
  std::string command_line_;
  // The time the output was created.
  Time creation_time_;
  // The version of the toolchain that produced the output.
  SyzygyVersion toolchain_version_;
  // The original module from/for which the output was produced.
  PEFile::Signature module_signature_;

  DISALLOW_COPY_AND_ASSIGN(Metadata);
};

}  // namespace pe

#endif  // SYZYGY_PE_METADATA_H_

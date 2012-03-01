// Copyright 2012 Google Inc.
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

#include "syzygy/playback/playback.h"

#include "syzygy/pdb/omap.h"
#include "syzygy/pe/find.h"
#include "syzygy/pe/metadata.h"
#include "syzygy/pe/pe_file.h"

namespace playback {

using block_graph::BlockGraph;
using trace::parser::Parser;

Playback::Playback(const FilePath& module_path,
                   const FilePath& instrumented_path,
                   const TraceFileList& trace_files)
    : module_path_(module_path),
      instrumented_path_(instrumented_path),
      trace_files_(trace_files),
      pe_file_(NULL),
      image_(NULL),
      parser_(NULL) {
}

Playback::~Playback() {
  pe_file_ = NULL;
  image_ = NULL;
  parser_ = NULL;
}

bool Playback::Init(PEFile* pe_file, ImageLayout* image, Parser* parser) {
  // Fail if the function was already initialized,
  // or if the parameters aren't.
  DCHECK(pe_file != NULL);
  DCHECK(image != NULL);
  DCHECK(parser != NULL);

  DCHECK(pe_file_ == NULL);
  DCHECK(image_ == NULL);
  DCHECK(parser_ == NULL);

  pe_file_ = pe_file;
  image_ = image;
  parser_ = parser;

  // Load and decompose the module.
  if (!LoadModuleInformation())
    return false;
  if (!InitializeParser())
    return false;
  if (!LoadInstrumentedOmap())
    return false;
  if (!DecomposeImage())
    return false;

  return true;
}

bool Playback::LoadModuleInformation() {
  DCHECK(pe_file_ != NULL);
  DCHECK(image_ != NULL);

  // Validate the instrumented module, and extract the signature of the original
  // module it was built from.
  pe::PEFile::Signature orig_signature;
  if (!ValidateInstrumentedModuleAndParseSignature(&orig_signature))
    return false;

  // If the input DLL path is empty, use the inferred one from the
  // instrumented module.
  if (module_path_.empty()) {
    LOG(INFO) << "Inferring input DLL path from instrumented module: "
              << orig_signature.path;
    module_path_ = FilePath(orig_signature.path);
  }

  // Try to read the input DLL.
  LOG(INFO) << "Reading input DLL.";
  if (!pe_file_->Init(module_path_)) {
    LOG(ERROR) << "Unable to read input image: " << module_path_.value();
    return false;
  }
  pe::PEFile::Signature input_signature;
  pe_file_->GetSignature(&input_signature);

  // Validate that the input DLL signature matches the original signature
  // extracted from the instrumented module.
  if (!orig_signature.IsConsistent(input_signature)) {
    LOG(ERROR) << "Instrumented module metadata does not match input module.";
    return false;
  }

  return true;
}

bool Playback::InitializeParser() {
  // Open the log files. We do this before running the decomposer as if these
  // fail we'll have wasted a lot of time!

  for (TraceFileIter i = trace_files_.begin(); i < trace_files_.end(); ++i) {
    const FilePath& trace_path = *i;
    LOG(INFO) << "Opening '" << trace_path.BaseName().value() << "'.";
    if (!parser_->OpenTraceFile(trace_path)) {
      LOG(ERROR) << "Unable to open trace log: " << trace_path.value();
      return false;
    }
  }

  return true;
}

bool Playback::LoadInstrumentedOmap() {
  // Find the PDB file for the instrumented module.
  FilePath instrumented_pdb;
  if (!pe::FindPdbForModule(instrumented_path_, &instrumented_pdb) ||
      instrumented_pdb.empty()) {
    LOG(ERROR) << "Unable to find PDB for instrumented image \""
               << instrumented_path_.value() << "\".";
    return false;
  }
  LOG(INFO) << "Found PDB for instrumented module: \""
            << instrumented_pdb.value() << "\".";

  // Load the OMAPTO table from the instrumented PDB. This will allow us to map
  // call-trace event addresses to addresses in the original image.
  if (!pdb::ReadOmapsFromPdbFile(instrumented_pdb, &omap_to_, &omap_from_)) {
    LOG(ERROR) << "Failed to read OMAPTO vector from PDB \""
               << instrumented_pdb.value() << "\".";
    return false;
  }
  LOG(INFO) << "Read OMAP data from instrumented module PDB.";

  return true;
}

bool Playback::DecomposeImage() {
  DCHECK(pe_file_ != NULL);
  DCHECK(image_ != NULL);

  // Decompose the DLL to be reordered. This will let us map call-trace events
  // to actual Blocks.
  LOG(INFO) << "Decomposing input image.";
  Decomposer decomposer(*pe_file_);
  if (!decomposer.Decompose(image_)) {
    LOG(ERROR) << "Unable to decompose input image: " << module_path_.value();
    return false;
  }

  return true;
}

bool Playback::ValidateInstrumentedModuleAndParseSignature(
  pe::PEFile::Signature* orig_signature) {
  DCHECK(orig_signature != NULL);

  pe::PEFile pe_file;
  if (!pe_file.Init(instrumented_path_)) {
    LOG(ERROR) << "Unable to parse instrumented module: "
               << instrumented_path_.value();
    return false;
  }
  pe_file.GetSignature(&instr_signature_);

  // Load the metadata from the PE file. Validate the toolchain version and
  // return the original module signature.
  pe::Metadata metadata;
  if (!metadata.LoadFromPE(pe_file))
    return false;
  *orig_signature = metadata.module_signature();

  if (!common::kSyzygyVersion.IsCompatible(metadata.toolchain_version())) {
    LOG(ERROR) << "Module was instrumented with an incompatible version of "
               << "the toolchain: " << instrumented_path_.value();
    return false;
  }

  return true;
}

bool Playback::MatchesInstrumentedModuleSignature(
    const ModuleInformation& module_info) const {
  // On Windows XP gathered traces, only the module size is non-zero.
  if (module_info.image_checksum == 0 && module_info.time_date_stamp == 0) {
    // If the size matches, then check that the names fit.
    if (instr_signature_.module_size != module_info.module_size)
      return false;

    FilePath base_name = instrumented_path_.BaseName();
    return (module_info.image_file_name.rfind(base_name.value()) !=
        std::wstring::npos);
  } else {
    // On Vista and greater, we can check the full module signature.
    return (instr_signature_.module_checksum == module_info.image_checksum &&
        instr_signature_.module_size == module_info.module_size &&
        instr_signature_.module_time_date_stamp == module_info.time_date_stamp);
  }
}

}  // namespace playback

// Copyright 2013 Google Inc. All Rights Reserved.
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

#include "syzygy/optimize/optimize_app.h"

#include "syzygy/block_graph/block_graph.h"
#include "syzygy/block_graph/transforms/chained_basic_block_transforms.h"
#include "syzygy/block_graph/transforms/fuzzing_transform.h"
#include "syzygy/block_graph/transforms/named_transform.h"
#include "syzygy/common/indexed_frequency_data.h"
#include "syzygy/grinder/basic_block_util.h"
#include "syzygy/optimize/application_profile.h"
#include "syzygy/optimize/transforms/block_alignment_transform.h"
#include "syzygy/optimize/transforms/inlining_transform.h"
#include "syzygy/pe/pe_relinker.h"
#include "syzygy/pe/pe_transform_policy.h"

namespace optimize {

namespace {

using block_graph::transforms::ChainedBasicBlockTransforms;
using block_graph::transforms::FuzzingTransform;
using common::IndexedFrequencyData;
using grinder::basic_block_util::IndexedFrequencyMap;
using grinder::basic_block_util::LoadBranchStatisticsFromFile;
using optimize::transforms::BlockAlignmentTransform;
using optimize::transforms::InliningTransform;

const char kUsageFormatStr[] =
    "Usage: %ls [options]\n"
    "  Required Options:\n"
    "    --input-image=<path>  The input image file to optimize.\n"
    "    --output-image=<path> Output path for the rewritten image file.\n"
    "\n"
    "  Options:\n"
    "    --branch-file=<path>  Branch statistics in JSON format.\n"
    "    --input-pdb=<path>    The PDB file associated with the input DLL.\n"
    "                          Default is inferred from input-image.\n"
    "    --output-pdb=<path>   Output path for the rewritten PDB file.\n"
    "                          Default is inferred from output-image.\n"
    "    --overwrite           Allow output files to be overwritten.\n"
    "\n"
    "  Testing Options:\n"
    "    --fuzz                Fuzz the binary.\n"
    "\n";

}  // namespace

bool OptimizeApp::ParseCommandLine(const CommandLine* cmd_line) {

  if (cmd_line->HasSwitch("help"))
     return Usage(cmd_line, "");

  input_image_path_ = AbsolutePath(cmd_line->GetSwitchValuePath("input-image"));
  output_image_path_ = cmd_line->GetSwitchValuePath("output-image");
  input_pdb_path_ = AbsolutePath(cmd_line->GetSwitchValuePath("input-pdb"));
  output_pdb_path_ = cmd_line->GetSwitchValuePath("output-pdb");
  branch_file_path_ = AbsolutePath(cmd_line->GetSwitchValuePath("branch-file"));

  overwrite_ = cmd_line->HasSwitch("overwrite");
  inlining_ = cmd_line->HasSwitch("inlining");
  block_alignment_ = cmd_line->HasSwitch("block-alignment");
  fuzz_ = cmd_line->HasSwitch("fuzz");

  // The --input-image argument is required.
  if (input_image_path_.empty())
    return Usage(cmd_line, "You must specify --input-image.");

  // The --output-image argument is required.
  if (output_image_path_.empty())
    return Usage(cmd_line, "You must specify --output-image.");

  return true;
}

bool OptimizeApp::SetUp() {
  DCHECK(!input_image_path_.empty());
  DCHECK(!output_image_path_.empty());
  return true;
}

int OptimizeApp::Run() {
  pe::PETransformPolicy policy;
  pe::PERelinker relinker(&policy);
  relinker.set_input_path(input_image_path_);
  relinker.set_input_pdb_path(input_pdb_path_);
  relinker.set_output_path(output_image_path_);
  relinker.set_output_pdb_path(output_pdb_path_);
  relinker.set_allow_overwrite(overwrite_);

  // Initialize the relinker. This does the decomposition, etc.
  if (!relinker.Init()) {
    LOG(ERROR) << "Failed to initialize relinker.";
    return 1;
  }

  // Get module signature and layout.
  pe::PEFile::Signature signature;
  relinker.input_pe_file().GetSignature(&signature);
  const pe::ImageLayout& image_layout = relinker.input_image_layout();

  // Load profile information from file.
  ApplicationProfile profile(&image_layout);
  if (!branch_file_path_.empty()) {
    IndexedFrequencyMap frequencies;
    if (!LoadBranchStatisticsFromFile(branch_file_path_,
                                      signature,
                                      &frequencies)) {
      LOG(ERROR) << "Unable to load profile information.";
      return 1;
    }
    if (!profile.ImportFrequencies(frequencies)) {
      LOG(ERROR) << "Could not import metrics for '"
                 << branch_file_path_.value() << "'.";
      return false;
    }
  }

  // Compute global profile information for the current block graph.
  if (!profile.ComputeGlobalProfile()) {
    LOG(ERROR) << "Unable to build profile information.";
    return 1;
  }

  // Construct a chain of basic block transforms.
  ChainedBasicBlockTransforms chains;

  // Declare transforms we may apply.
  scoped_ptr<InliningTransform> inlining_transform;
  scoped_ptr<BlockAlignmentTransform> block_alignment_transform;
  scoped_ptr<FuzzingTransform> fuzzing_transform;

  // If inlining is enabled, add it to the chain.
  if (inlining_) {
    inlining_transform.reset(new InliningTransform(&profile));
    CHECK(chains.AppendTransform(inlining_transform.get()));
  }

  // If block alignment is enabled, add it to the chain.
  if (block_alignment_) {
    block_alignment_transform.reset(new BlockAlignmentTransform());
    CHECK(chains.AppendTransform(block_alignment_transform.get()));
  }

  // Append the chain to the relinker.
  if (!relinker.AppendTransform(&chains))
    return false;

  // If fuzzing is enabled, add it to the chain.
  if (fuzz_) {
    fuzzing_transform.reset(new block_graph::transforms::FuzzingTransform);
    CHECK(relinker.AppendTransform(fuzzing_transform.get()));
  }

  // Perform the actual relink.
  if (!relinker.Relink()) {
    LOG(ERROR) << "Unable to relink input image.";
    return 1;
  }

  return 0;
}

bool OptimizeApp::Usage(const CommandLine* cmd_line,
                        const base::StringPiece& message) const {
  if (!message.empty()) {
    ::fwrite(message.data(), 1, message.length(), err());
    ::fprintf(err(), "\n\n");
  }

  ::fprintf(err(),
            kUsageFormatStr,
            cmd_line->GetProgram().BaseName().value().c_str());

  return false;
}

}  // namespace optimize

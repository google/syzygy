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

#include "syzygy/instrument/instrumenters/instrumenter_with_relinker.h"

#include "base/logging.h"
#include "base/files/file_util.h"
#include "syzygy/application/application.h"
#include "syzygy/core/file_util.h"

namespace instrument {
namespace instrumenters {

namespace {

using block_graph::BlockGraph;

bool GetImageFormat(const base::FilePath& path,
                    BlockGraph::ImageFormat* image_format) {
  DCHECK(image_format != nullptr);

  // Determine the type of the input.
  core::FileType file_type = core::kUnknownFileType;
  if (!core::GuessFileType(path, &file_type)) {
    LOG(ERROR) << "Failed to determine file type of \""
               << path.value() << "\".";
    return false;
  }

  if (file_type == core::kCoffFileType) {
    *image_format = BlockGraph::COFF_IMAGE;
    return true;
  }

  if (file_type == core::kPeFileType) {
    *image_format = BlockGraph::PE_IMAGE;
    return true;
  }

  LOG(ERROR) << "File is not a PE or COFF image: " << path.value();
  return false;
}

}  // namespace

bool InstrumenterWithRelinker::ParseCommandLine(
    const base::CommandLine* command_line) {
  return DoCommandLineParse(command_line) &&
      CheckCommandLineParse(command_line);
}

bool InstrumenterWithRelinker::DoCommandLineParse(
    const base::CommandLine* command_line) {
  DCHECK(command_line != nullptr);
  // No super class.

  // TODO(chrisha): Simplify the input/output image parsing once external
  //     tools have been updated.

  // Parse the input image.
  if (command_line->HasSwitch("input-dll")) {
    LOG(WARNING) << "DEPRECATED: Using --input-dll.";
    input_image_path_ = application::AppImplBase::AbsolutePath(
        command_line->GetSwitchValuePath("input-dll"));
  } else {
    input_image_path_ = application::AppImplBase::AbsolutePath(
        command_line->GetSwitchValuePath("input-image"));
  }

  // Parse the output image.
  if (command_line->HasSwitch("output-dll")) {
    LOG(WARNING) << "DEPRECATED: Using --output-dll.";
    output_image_path_ = application::AppImplBase::AbsolutePath(
        command_line->GetSwitchValuePath("output-dll"));
  } else {
    output_image_path_ = application::AppImplBase::AbsolutePath(
        command_line->GetSwitchValuePath("output-image"));
  }

  // Ensure that both input and output have been specified.
  if (input_image_path_.empty() || output_image_path_.empty()) {
    LOG(ERROR) << "You must provide input and output file names.";
    return false;
  }

  // Parse the remaining command line arguments.
  input_pdb_path_ = application::AppImplBase::AbsolutePath(
      command_line->GetSwitchValuePath("input-pdb"));
  output_pdb_path_ = application::AppImplBase::AbsolutePath(
      command_line->GetSwitchValuePath("output-pdb"));
  allow_overwrite_ = command_line->HasSwitch("overwrite");
  debug_friendly_ = command_line->HasSwitch("debug-friendly");
  no_augment_pdb_ = command_line->HasSwitch("no-augment-pdb");
  no_strip_strings_ = command_line->HasSwitch("no-strip-strings");

  return true;
}

bool InstrumenterWithRelinker::CheckCommandLineParse(
    const base::CommandLine* command_line) {
  return true;  // No super class.
}

bool InstrumenterWithRelinker::Instrument() {
  if (!InstrumentPrepare())
    return false;

  if (!CreateRelinker())
    return false;

  // Initialize the relinker. This does the decomposition, etc.
  if (!relinker_->Init()) {
    LOG(ERROR) << "Failed to initialize relinker.";
    return false;
  }

  // Let the instrumenter implementation set up the relinker and anything else
  // that is required.
  if (!InstrumentImpl())
    return false;

  // Do the actual instrumentation by running the relinker.
  if (!relinker_->Relink()) {
    LOG(ERROR) << "Unable to relink input image.";
    return false;
  }

  return true;
}

bool InstrumenterWithRelinker::ImageFormatIsSupported(
    BlockGraph::ImageFormat image_format) {
  // By default we only support PE images.
  if (image_format == BlockGraph::PE_IMAGE)
    return true;
  return false;
}

pe::PETransformPolicy* InstrumenterWithRelinker::GetPETransformPolicy() {
  DCHECK_EQ(BlockGraph::PE_IMAGE, image_format_);
  DCHECK(policy_object_.get() == nullptr);
  policy_object_.reset(new pe::PETransformPolicy());
  return static_cast<pe::PETransformPolicy*>(policy_object_.get());
}

pe::CoffTransformPolicy* InstrumenterWithRelinker::GetCoffTransformPolicy() {
  DCHECK_EQ(BlockGraph::COFF_IMAGE, image_format_);
  DCHECK(policy_object_.get() == nullptr);
  policy_object_.reset(new pe::CoffTransformPolicy());
  return static_cast<pe::CoffTransformPolicy*>(policy_object_.get());
}

pe::PERelinker* InstrumenterWithRelinker::GetPERelinker() {
  DCHECK_EQ(BlockGraph::PE_IMAGE, image_format_);
  DCHECK(relinker_object_.get() == nullptr);
  relinker_object_.reset(new pe::PERelinker(GetPETransformPolicy()));
  return static_cast<pe::PERelinker*>(relinker_object_.get());
}

pe::CoffRelinker* InstrumenterWithRelinker::GetCoffRelinker() {
  DCHECK_EQ(BlockGraph::COFF_IMAGE, image_format_);
  relinker_object_.reset(new pe::CoffRelinker(GetCoffTransformPolicy()));
  return static_cast<pe::CoffRelinker*>(relinker_object_.get());
}

bool InstrumenterWithRelinker::CreateRelinker() {
  // Get the image format by quickly inspecting the image. This logs verbosely
  // on failure.
  if (!GetImageFormat(input_image_path_, &image_format_))
    return false;

  // Check if the format is supported and bail if it isn't.
  if (!ImageFormatIsSupported(image_format_)) {
    LOG(ERROR) << "Instrumenter \"" << InstrumentationMode()
               << "\" does not support input image format.";
    return false;
  }

  // Create and setup an image format specific relinker.
  if (image_format_ == BlockGraph::COFF_IMAGE) {
    pe::CoffRelinker* relinker = GetCoffRelinker();
    DCHECK_NE(reinterpret_cast<pe::CoffRelinker*>(nullptr), relinker);
    relinker_ = relinker;
    relinker->set_input_path(input_image_path_);
    relinker->set_output_path(output_image_path_);
    relinker->set_allow_overwrite(allow_overwrite_);
  } else {
    pe::PERelinker* relinker = GetPERelinker();
    DCHECK_NE(reinterpret_cast<pe::PERelinker*>(nullptr), relinker);
    relinker_ = relinker;
    relinker->set_input_path(input_image_path_);
    relinker->set_input_pdb_path(input_pdb_path_);
    relinker->set_output_path(output_image_path_);
    relinker->set_output_pdb_path(output_pdb_path_);
    relinker->set_allow_overwrite(allow_overwrite_);
    relinker->set_augment_pdb(!no_augment_pdb_);
    relinker->set_strip_strings(!no_strip_strings_);
  }

  DCHECK_EQ(image_format_, relinker_->image_format());

  return true;
}

}  // namespace instrumenters
}  // namespace instrument

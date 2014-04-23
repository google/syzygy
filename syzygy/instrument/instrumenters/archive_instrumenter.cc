// Copyright 2014 Google Inc. All Rights Reserved.
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
// Instrumentation adapter that adds archive support to any existing
// instrumenter. Takes care of instantiating a new instance of the
// underlying instrumenter for each file in the archive. When not processing
// an archive simply passes through the original instrumenter.

#include "syzygy/instrument/instrumenters/archive_instrumenter.h"

#include "base/bind.h"
#include "base/file_util.h"
#include "syzygy/ar/ar_transform.h"
#include "syzygy/pe/pe_utils.h"

namespace instrument {
namespace instrumenters {

namespace {

const char kInputImage[] = "input-image";
const char kOutputImage[] = "output-image";

}  // namespace

ArchiveInstrumenter::ArchiveInstrumenter()
    : factory_(NULL), overwrite_(false) {
}

ArchiveInstrumenter::ArchiveInstrumenter(InstrumenterFactoryFunction factory)
    : factory_(factory), overwrite_(false) {
  DCHECK_NE(reinterpret_cast<InstrumenterFactoryFunction>(NULL), factory);
}

bool ArchiveInstrumenter::ParseCommandLine(const CommandLine* command_line) {
  DCHECK_NE(reinterpret_cast<CommandLine*>(NULL), command_line);

  // Create a copy of the command-line.
  command_line_.reset(new CommandLine(*command_line));

  // Parse the few parameters that we care about.
  input_image_ = command_line_->GetSwitchValuePath(kInputImage);
  output_image_ = command_line_->GetSwitchValuePath(kOutputImage);
  overwrite_ = command_line_->HasSwitch("overwrite");

  return true;
}

bool ArchiveInstrumenter::Instrument() {
  DCHECK_NE(reinterpret_cast<InstrumenterFactoryFunction>(NULL), factory_);

  if (ProcessingArchive()) {
    if (!InstrumentArchive())
      return false;
  } else {
    if (!InstrumentPassthrough())
      return false;
  }

  return true;
}

bool ArchiveInstrumenter::ProcessingArchive() const {
  if (input_image_.empty() || output_image_.empty())
    return false;

  if (!file_util::PathExists(input_image_))
    return false;

  pe::FileType file_type = pe::kUnknownFileType;
  if (!pe::GuessFileType(input_image_, &file_type))
    return false;

  if (file_type == pe::kArchiveFileType)
    return true;

  return false;
}

bool ArchiveInstrumenter::InstrumentPassthrough() {
  DCHECK_NE(reinterpret_cast<InstrumenterFactoryFunction>(NULL), factory_);

  scoped_ptr<InstrumenterInterface> instrumenter(factory_());
  DCHECK_NE(reinterpret_cast<InstrumenterInterface*>(NULL),
            instrumenter.get());

  if (!instrumenter->ParseCommandLine(command_line_.get()))
    return false;

  if (!instrumenter->Instrument())
    return false;

  return true;
}

bool ArchiveInstrumenter::InstrumentArchive() {
  // Ensure we're not accidentally going to be overwriting the output.
  if (!overwrite_ && file_util::PathExists(output_image_)) {
    LOG(ERROR) << "Output path exists. Did you want to specify --overwrite?";
    return false;
  }

  LOG(INFO) << "Instrumenting archive: " << input_image_.value();

  // Configure and run an archive transform.
  ar::OnDiskArTransformAdapter::TransformFileOnDiskCallback callback =
      base::Bind(&ArchiveInstrumenter::InstrumentFile, base::Unretained(this));
  ar::OnDiskArTransformAdapter on_disk_adapter(callback);
  ar::ArTransform ar_transform;
  ar_transform.set_callback(on_disk_adapter.outer_callback());
  ar_transform.set_input_archive(input_image_);
  ar_transform.set_output_archive(output_image_);
  if (!ar_transform.Transform())
    return false;

  return true;
}

bool ArchiveInstrumenter::InstrumentFile(const base::FilePath& input_path,
                                         const base::FilePath& output_path,
                                         ar::ParsedArFileHeader* header,
                                         bool* remove) {
  DCHECK_NE(reinterpret_cast<InstrumenterFactoryFunction>(NULL), factory_);
  DCHECK_NE(reinterpret_cast<ar::ParsedArFileHeader*>(NULL), header);
  DCHECK_NE(reinterpret_cast<bool*>(NULL), remove);

  // We don't want to delete the file from the archive.
  *remove = false;

  // Filter anything that isn't a known and recognized COFF file.
  pe::FileType file_type = pe::kUnknownFileType;
  if (!pe::GuessFileType(input_path, &file_type)) {
    LOG(ERROR) << "Unable to determine file type.";
    return false;
  }
  if (file_type != pe::kCoffFileType) {
    LOG(INFO) << "Not processing non-object file.";
    if (!file_util::CopyFile(input_path, output_path)) {
      LOG(ERROR) << "Unable to write output file: " << output_path.value();
      return false;
    }
    return true;
  }

  // Create the command-line for the child instrumenter.
  CommandLine command_line(*command_line_.get());
  command_line.AppendSwitchPath(kInputImage, input_path);
  command_line.AppendSwitchPath(kOutputImage, output_path);

  // Create, initialize and run an instrumenter.
  scoped_ptr<InstrumenterInterface> instrumenter(factory_());
  DCHECK_NE(reinterpret_cast<InstrumenterInterface*>(NULL),
            instrumenter.get());
  if (!instrumenter->ParseCommandLine(&command_line))
    return false;
  if (!instrumenter->Instrument())
    return false;

  return true;
}

}  // namespace instrumenters
}  // namespace instrument

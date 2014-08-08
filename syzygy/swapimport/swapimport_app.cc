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
// Defines the SwapImportApp class, which implements the command-line
// "swapimport" tool.

#include "syzygy/swapimport/swapimport_app.h"

#include "base/file_util.h"
#include "base/strings/string_util.h"
#include "base/strings/utf_string_conversions.h"
#include "syzygy/core/file_util.h"
#include "syzygy/pe/pe_file.h"
#include "syzygy/pe/pe_file_writer.h"

namespace swapimport {

namespace {

static const char kUsageFormatStr[] = "Usage: %ls [options] IMPORT\n"
    "  Required Options:\n"
    "    --input-image=PATH    Path of the input image.\n"
    "    --output-image=PATH   Path where the output image will be written.\n"
    "                          The generated image will still be paired to\n"
    "                          the original PDB file.\n"
    "    --x64                 Decompose a 64-bit binary rather than a\n"
    "                          32-bit one.\n"
    "  Options:\n"
    "    --overwrite           Allow output files to be overwritten.\n"
    "    --verbose             Log verbosely.\n"
    "\n";

}  // namespace

bool SwapImportApp::ParseCommandLine(const CommandLine* cmd_line) {
  DCHECK_NE(reinterpret_cast<const CommandLine*>(NULL), cmd_line);

  if (cmd_line->HasSwitch("help"))
    return Usage(cmd_line, "");

  if (cmd_line->HasSwitch("verbose")) {
    logging::SetMinLogLevel(logging::LOG_VERBOSE);
    VLOG(1) << "Parsed --verbose switch.";
  } else {
    logging::SetMinLogLevel(logging::LOG_ERROR);
  }

  input_image_ = cmd_line->GetSwitchValuePath("input-image");
  if (input_image_.empty()) {
    LOG(ERROR) << "Must specify --input-image!";
    return false;
  }

  output_image_ = cmd_line->GetSwitchValuePath("output-image");
  if (output_image_.empty()) {
    LOG(ERROR) << "Must specify --output-image!";
    return false;
  }

  overwrite_ = cmd_line->HasSwitch("overwrite");
  if (overwrite_)
    VLOG(1) << "Parsed --overwrite switch.";

  CommandLine::StringVector args = cmd_line->GetArgs();
  if (args.size() != 1) {
    LOG(ERROR) << "Expect exactly one import name.";
    return false;
  }
  import_name_ = base::WideToUTF8(args[0]);

  x64_ = cmd_line->HasSwitch("x64");
  if (x64_)
    VLOG(1) << "Parsed --x64 switch.";

  return true;
}

template <typename PEFileType>
int SwapImportApp::SwapImports() {
  // Parse the input file as a PE image.
  PEFileType pe_file;
  if (!pe_file.Init(input_image_)) {
    LOG(ERROR) << "Failed to parse image as a PE file: "
               << input_image_.value();
      return 1;
  }

  // Read the entire input into memory.
  VLOG(1) << "Reading \"" << input_image_.value() << "\" into memory.";
  int64 image_size = 0;
  if (!base::GetFileSize(input_image_, &image_size)) {
    LOG(ERROR) << "Failed to get image size: " << input_image_.value();
    return 1;
  }
  std::vector<unsigned char> image(image_size, 0);
  if (!base::ReadFile(input_image_,
                           reinterpret_cast<char*>(image.data()),
                           image_size)) {
    LOG(ERROR) << "Failed to read image to memory: " << input_image_.value();
    return 1;
  }

  // Keeps track of matched imports, and how many have been swapped.
  size_t imports_swapped = 0;
  size_t imports_matched = 0;

  // Look up the import directory.
  LOG(INFO) << "Processing NT headers.";
  const IMAGE_DATA_DIRECTORY* data_dir =
      pe_file.nt_headers()->OptionalHeader.DataDirectory +
          IMAGE_DIRECTORY_ENTRY_IMPORT;
  if (data_dir->Size != 0) {
    LOG(INFO) << "Processing imports.";

    pe::PEFile::FileOffsetAddress import_offset;
    if (!pe_file.Translate(
            pe::PEFile::RelativeAddress(data_dir->VirtualAddress),
            &import_offset)) {
      LOG(ERROR) << "Failed to translate import directory address.";
      return 1;
    }

    // Walk over the imports.
    IMAGE_IMPORT_DESCRIPTOR* imports_begin =
        reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
            image.data() + import_offset.value());
    IMAGE_IMPORT_DESCRIPTOR* imports_end =
        reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
            image.data() + import_offset.value() + data_dir->Size);
    IMAGE_IMPORT_DESCRIPTOR* imports = imports_begin;
    size_t import_index = 0;
    while (imports < imports_end && imports->Characteristics != 0) {
      // Look up the import name.
      pe::PEFile::FileOffsetAddress name_offset;
      if (!pe_file.Translate(
              pe::PEFile::RelativeAddress(imports->Name),
              &name_offset)) {
        LOG(ERROR) << "Failed to translate import name.";
        return 1;
      }

      // Compare the import name.
      const char* name = reinterpret_cast<const char*>(
          image.data() + name_offset.value());
      VLOG(1) << "Processing import " << import_index << " \""
              << name << "\".";
      if (base::strcasecmp(import_name_.c_str(), name) == 0) {
        VLOG(1) << "Import " << import_index << " matches import name.";
        ++imports_matched;

        if (import_index > imports_swapped) {
          // Do the actual swapping of the imports.
          LOG(INFO) << "Swapping imports " << imports_swapped << " and "
                    << import_index;

          IMAGE_IMPORT_DESCRIPTOR temp_iid = *imports;
          *imports = imports_begin[imports_swapped];
          imports_begin[imports_swapped] = temp_iid;

          ++imports_swapped;
        }
      }

      ++imports;
      ++import_index;
    }
  }

  // We expect to have matched the specified import at least once.
  if (imports_matched == 0) {
    LOG(ERROR) << "Did not find an import matching \"" << import_name_ << "\".";
    return 1;
  }

  // Write the actual output.
  LOG(INFO) << "Writing output to \"" << output_image_.value() << "\".";
  base::ScopedFILE output(base::OpenFile(output_image_, "wb"));
  if (output.get() == NULL) {
    LOG(ERROR) << "Failed to open \"" << output_image_.value() << "\" for "
               << "writing.";
    return 1;
  }
  if (::fwrite(image.data(), sizeof(image[0]), image.size(), output.get()) !=
          image.size()) {
    LOG(ERROR) << "Failed to write output: " << output_image_.value();
    return 1;
  }
  output.reset();

  // Finalize the image by updating the checksum.
  LOG(INFO) << "Updating output image checksum.";
  if (!pe::PEFileWriter::UpdateFileChecksum(output_image_)) {
    LOG(ERROR) << "Failed to update image checksum.";
    return 1;
  }

  return 0;
}

int SwapImportApp::Run() {
  // Check the input.
  if (!base::PathExists(input_image_)) {
    LOG(ERROR) << "Path does not exist: " << input_image_.value();
    return 1;
  }

  // Check the output unless we're overwriting.
  if (!overwrite_) {
    if (base::PathExists(output_image_)) {
      LOG(ERROR) << "Output path exists: " << output_image_.value();
      LOG(ERROR) << "Did you mean to specify --overwrite?";
      return 1;
    }

    core::FilePathCompareResult result = core::CompareFilePaths(
        input_image_, output_image_);
    if (result == core::kEquivalentFilePaths) {
      LOG(ERROR) << "Output image path equivalent to input image path.";
      return 1;
    }
  }

  if (x64_) {
    return SwapImports<pe::PEFile64>();
  } else {
    return SwapImports<pe::PEFile>();
  }
}

bool SwapImportApp::Usage(const CommandLine* cmd_line,
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

}  // namespace swapimport

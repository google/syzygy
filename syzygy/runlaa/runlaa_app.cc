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

#include "syzygy/runlaa/runlaa_app.h"

#include "base/path_service.h"
#include "base/files/file_util.h"
#include "base/files/scoped_temp_dir.h"
#include "base/process/launch.h"
#include "base/win/pe_image.h"
#include "syzygy/core/file_util.h"
#include "syzygy/pe/pe_file.h"

namespace runlaa {

namespace {

static const char kUsageFormatStr[] =
    "Usage: %ls [options] -- [options for child process]\n"
    "Required Options:\n"
    "  --image=<FILE>   Path of the image to run."
    "  --mode=<MODE>    Runs the provided executable with the given mode.\n"
    "                   MODE must be one of 'laa' or 'nolaa'.\n"
    "Optional Options:\n"
    "  --expect-mode=<MODE>\n"
    "                   If specified then returns 0 if the currently running\n"
    "                   mode matches the expected mode, 1 otherwise. This is\n"
    "                   to allow self-unittesting.\n"
    "  --in-place       Modifies the image in-place if necessary. Returns the\n"
    "                   image to its original state when completed.\n"
    "  --keep-temp-dir  If specified then the temp directory will not be\n"
    "                   deleted.\n"
    "\n";

static const char kInPlace[] = "in-place";
static const char kImage[] = "image";
static const char kKeepTempDir[] = "keep-temp-dir";
static const char kMode[] = "mode";
static const char kModeLaa[] = "laa";
static const char kModeNoLaa[] = "nolaa";

// Gets the status of the LargeAddressAware bit for the given image.
bool GetLaaBit(const base::FilePath& image_path, bool* is_laa) {
  DCHECK_NE(static_cast<bool*>(nullptr), is_laa);

  if (!base::PathExists(image_path)) {
    LOG(ERROR) << "Image does not exist: " << image_path.value();
    return false;
  }

  pe::PEFile image;
  if (!image.Init(image_path)) {
    LOG(ERROR) << "Unable to open PE file: " << image_path.value();
    return false;
  }

  *is_laa = (image.nt_headers()->FileHeader.Characteristics &
             IMAGE_FILE_LARGE_ADDRESS_AWARE) != 0;

  return true;
}

// Toggles the LargeAddressAware bit for the given image.
bool ToggleLaaBit(const base::FilePath& image_path) {
  base::ScopedFILE file(base::OpenFile(image_path, "r+b"));
  if (file.get() == nullptr) {
    LOG(ERROR) << "Unable to open for reading and writing: "
               << image_path.value();
    return false;
  }

  // Read the DOS header.
  IMAGE_DOS_HEADER dos_header = {};
  if (fread(&dos_header, sizeof(dos_header), 1, file.get()) != 1) {
    LOG(ERROR) << "Unable to read DOS header:" << image_path.value();
    return false;
  }

  // Get the offset of the image characteristics.
  size_t characteristics_offset = dos_header.e_lfanew +
                                  offsetof(IMAGE_NT_HEADERS, FileHeader) +
                                  offsetof(IMAGE_FILE_HEADER, Characteristics);
  WORD characteristics = 0;
  if (::fseek(file.get(), characteristics_offset, SEEK_SET) != 0 ||
      ::fread(&characteristics, sizeof(characteristics), 1, file.get()) != 1) {
    LOG(ERROR) << "Unable to read image characteristics: "
               << image_path.value();
    return false;
  }

  // Toggle the bit and write it back to the image.
  characteristics ^= IMAGE_FILE_LARGE_ADDRESS_AWARE;
  if (::fseek(file.get(), characteristics_offset, SEEK_SET) != 0 ||
      ::fwrite(&characteristics, sizeof(characteristics), 1, file.get()) != 1) {
    LOG(ERROR) << "Unable to write image characteristics: "
               << image_path.value();
    return false;
  }

  return true;
}

bool CurrentProcessIsLargeAddressAware() {
  const base::win::PEImage image(::GetModuleHandle(NULL));

  bool process_is_large_address_aware =
      (image.GetNTHeaders()->FileHeader.Characteristics &
       IMAGE_FILE_LARGE_ADDRESS_AWARE) != 0;

  return process_is_large_address_aware;
}

bool SelfTest(const std::string& expect_mode) {
  bool is_laa = CurrentProcessIsLargeAddressAware();
  if (expect_mode == kModeLaa)
    return is_laa;
  if (expect_mode == kModeNoLaa)
    return !is_laa;
  return false;
}

}  // namespace

bool RunLaaApp::ParseCommandLine(const base::CommandLine* command_line) {
  DCHECK_NE(static_cast<const base::CommandLine*>(nullptr), command_line);

  if (command_line->HasSwitch("help")) {
    ::fprintf(err(), kUsageFormatStr,
              command_line->GetProgram().BaseName().value().c_str());
    return false;
  }

  // If the executable is running a self-hosted test, then don't bother parsing
  // anything else.
  expect_mode_ = command_line->GetSwitchValueASCII("expect-mode");
  if (!expect_mode_.empty())
    return true;

  // Parse the image.
  if (!command_line->HasSwitch(kImage)) {
    LOG(ERROR) << "Must specify --" << kImage << ".";
    return false;
  }
  image_ = base::MakeAbsoluteFilePath(command_line->GetSwitchValuePath(kImage));

  // Parse the mode.
  if (!command_line->HasSwitch(kMode)) {
    LOG(ERROR) << "Must specify --" << kMode << ".";
    return false;
  }
  std::string mode;
  mode = command_line->GetSwitchValueASCII(kMode);
  if (mode == kModeLaa) {
    is_laa_ = true;
  } else if (mode == kModeNoLaa) {
    is_laa_ = false;
  } else {
    LOG(ERROR) << "Unrecognized mode: " << mode;
    return false;
  }

  // Parse optional options.
  in_place_ = command_line->HasSwitch(kInPlace);
  keep_temp_dir_ = command_line->HasSwitch(kKeepTempDir);

  // Copy the child process arguments.
  child_argv_ = command_line->GetArgs();

  return true;
}

int RunLaaApp::Run() {
  // If an expected mode has been specified then run a self-test and return
  // the result.
  if (!expect_mode_.empty()) {
    if (SelfTest(expect_mode_))
      return 0;
    return 1;
  }

  bool is_laa = false;
  if (!GetLaaBit(image_, &is_laa))
    return 1;

  base::ScopedTempDir scoped_temp_dir;
  base::FilePath child_image(image_);
  bool toggle_back = false;

  if (is_laa == is_laa_) {
    LOG(INFO) << "Image already in desired mode, running directly.";
  } else {
    // The image is not in the desired mode. It needs to be toggled.
    if (in_place_) {
      // Try our best not to modify the currently running executable.
      base::FilePath exe_path;
      if (PathService::Get(base::FILE_EXE, &exe_path)) {
        exe_path = base::MakeAbsoluteFilePath(exe_path);
        core::FilePathCompareResult result =
            core::CompareFilePaths(exe_path, image_);
        if (result == core::kEquivalentFilePaths) {
          LOG(ERROR) << "Unable to modify running executable in-place.";
          return 1;
        }
      }

      // The work is occurring in place and the image needs to be toggled back.
      toggle_back = true;
    } else {
      // The work is not to happen in place. Create a temp directory and copy
      // the
      // image.
      if (!scoped_temp_dir.CreateUniqueTempDir()) {
        LOG(ERROR) << "Failed to create temp directory.";
        return 1;
      }

      // Take ownership of the temp directory if it is to be left around.
      base::FilePath temp_dir = scoped_temp_dir.path();
      if (keep_temp_dir_) {
        temp_dir = scoped_temp_dir.Take();
        LOG(INFO) << "Temporary directory will be preserved: "
                  << temp_dir.value();
      }

      child_image = temp_dir.Append(image_.BaseName());
      LOG(INFO) << "Creating copy of image: " << child_image.value();
      if (!base::CopyFile(image_, child_image)) {
        LOG(ERROR) << "Failed to copy image.";
        return 1;
      }
    }

    // Toggle the image.
    LOG(INFO) << "Toggling LargeAddressAware bit: " << child_image.value();
    if (!ToggleLaaBit(child_image))
      return 1;
  }

  // Run the child process.
  base::CommandLine::StringVector child_argv(child_argv_);
  child_argv.insert(child_argv.begin(), child_image.value());
  base::CommandLine child_command_line(child_argv);
  LOG(INFO) << "Launching child process: "
            << child_command_line.GetCommandLineString();
  base::LaunchOptions launch_options;
  base::Process child_process =
      base::LaunchProcess(child_command_line, launch_options);
  DCHECK(child_process.IsValid());
  int exit_code = 0;
  child_process.WaitForExit(&exit_code);
  LOG(INFO) << "Child process returned " << exit_code;

  // Toggle the image back if need be.
  if (toggle_back) {
    // The assumption is that work was in place and the bit was previously
    // toggled.
    DCHECK_NE(is_laa, is_laa_);
    DCHECK_EQ(child_image.value(), image_.value());
    LOG(INFO) << "Toggling back LargeAddressAware bit.";
    if (!ToggleLaaBit(child_image))
      return 1;
  }

  // Return the exit code of the child process.
  return exit_code;
}

}  // namespace runlaa

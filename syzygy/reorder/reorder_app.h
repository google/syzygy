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

#ifndef SYZYGY_REORDER_REORDER_APP_H_
#define SYZYGY_REORDER_REORDER_APP_H_

#include "base/command_line.h"
#include "base/files/file_path.h"
#include "base/memory/scoped_ptr.h"
#include "base/strings/string_piece.h"
#include "base/time/time.h"
#include "syzygy/common/application.h"
#include "syzygy/pe/image_layout.h"
#include "syzygy/pe/pe_file.h"
#include "syzygy/reorder/reorderer.h"

namespace reorder {

// This class implements the command-line reorder utility.
class ReorderApp : public common::AppImplBase {
 public:
  ReorderApp();

  // @name Implementation of the AppImplBase interface.
  // @{
  bool ParseCommandLine(const CommandLine* command_line);
  bool SetUp();
  int Run();
  // @}

 protected:
  typedef std::vector<base::FilePath> FilePathVector;

  enum Mode {
    kInvalidMode,
    kLinearOrderMode,
    kRandomOrderMode,
    kDeadCodeFinderMode
  };
  // @name Utility members.
  // @{
  bool Usage(const CommandLine* command_line,
             const base::StringPiece& message) const;
  bool OptimizeBasicBlocks(const pe::PEFile::Signature& signature,
                           const pe::ImageLayout& image_layout,
                           Reorderer::Order* order);
  // @}

  Mode mode_;
  scoped_ptr<Reorderer::OrderGenerator> order_generator_;

  // @name Command-line parameters.
  // @{
  base::FilePath instrumented_image_path_;
  base::FilePath input_image_path_;
  base::FilePath output_file_path_;
  base::FilePath bb_entry_count_file_path_;
  FilePathVector trace_file_paths_;
  uint32 seed_;
  bool pretty_print_;
  Reorderer::Flags flags_;
  // @}

  // Command-line parameter names. Exposed as protected for unit-testing.
  // @{
  static const char kInstrumentedImage[];
  static const char kOutputFile[];
  static const char kInputImage[];
  static const char kBasicBlockEntryCounts[];
  static const char kSeed[];
  static const char kListDeadCode[];
  static const char kPrettyPrint[];
  static const char kReordererFlags[];
  static const char kInstrumentedDll[];
  static const char kInputDll[];
  // @}
 private:
  DISALLOW_COPY_AND_ASSIGN(ReorderApp);
};

}  // namespace reorder

#endif  // SYZYGY_REORDER_REORDER_APP_H_

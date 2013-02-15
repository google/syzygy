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
// Declares the coverage grinder, which processes trace files containing
// coverage data and produces LCOV output.
#ifndef SYZYGY_GRINDER_COVERAGE_GRINDER_H_
#define SYZYGY_GRINDER_COVERAGE_GRINDER_H_

#include "syzygy/grinder/basic_block_util.h"
#include "syzygy/grinder/coverage_data.h"
#include "syzygy/grinder/grinder.h"

namespace grinder {

// This class processes trace files containing basic-block frequency data and
// produces LCOV output.
class CoverageGrinder : public GrinderInterface {
 public:
  CoverageGrinder();
  ~CoverageGrinder();

  // @name GrinderInterface implementation.
  // @{
  virtual bool ParseCommandLine(const CommandLine* command_line) OVERRIDE;
  virtual void SetParser(Parser* parser) OVERRIDE;
  virtual bool Grind() OVERRIDE;
  virtual bool OutputData(FILE* file) OVERRIDE;
  // @}

  // @name IndexedFrequencyGrinder implementation.
  // @{
  // Override of the OnIndexedFrequency callback.
  // NOTE: This only process TraceIndexedFrequencyData records of the
  //    appropriate type (basic-block entry counts).
  virtual void OnIndexedFrequency(
      base::Time time,
      DWORD process_id,
      DWORD thread_id,
      const TraceIndexedFrequencyData* data) OVERRIDE;
  // @}

  enum OutputFormat {
    kLcovFormat,
    kCacheGrindFormat,
  };

  OutputFormat output_format() const { return output_format_; }

 protected:
  // Stores per-module coverage data, populated during calls to
  // OnIndexedFrequency.
  basic_block_util::PdbInfoMap pdb_info_cache_;

  // Stores the final coverage data, populated by Grind. Contains an aggregate
  // of all LineInfo objects stored in the pdb_info_map_, in a reverse map
  // (where efficient lookup is by file name and line number).
  CoverageData coverage_data_;

  // Points to the parser that is feeding us events. Used to get module
  // information.
  Parser* parser_;

  // Set to true if any call to OnIndexedFrequency fails. Processing will
  // continue with a warning that results may be partial.
  bool event_handler_errored_;

  // The output format to use.
  OutputFormat output_format_;
};

}  // namespace grinder

#endif  // SYZYGY_GRINDER_COVERAGE_GRINDER_H_

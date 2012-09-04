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
//
// Declares the coverage grinder, which processes trace files containing
// coverage data and produces LCOV output.
#ifndef SYZYGY_GRINDER_COVERAGE_GRINDER_H_
#define SYZYGY_GRINDER_COVERAGE_GRINDER_H_

#include "syzygy/grinder/grinder.h"

#include "syzygy/grinder/lcov_writer.h"
#include "syzygy/grinder/line_info.h"

namespace grinder {

class CoverageGrinder : public GrinderInterface {
 public:
  typedef core::RelativeAddress RelativeAddress;
  typedef core::AddressRange<RelativeAddress, size_t> RelativeAddressRange;
  typedef std::vector<RelativeAddressRange> RelativeAddressRangeVector;

  CoverageGrinder();
  ~CoverageGrinder();

  // @name GrinderInterface implementation.
  // @{
  virtual bool ParseCommandLine(const CommandLine* command_line) OVERRIDE;
  virtual void SetParser(Parser* parser) OVERRIDE;
  virtual bool Grind() OVERRIDE;
  virtual bool OutputData(FILE* file) OVERRIDE;
  // @}

  // @name ParseEventHandler overrides.
  // @{
  virtual void OnBasicBlockFrequency(
      base::Time time,
      DWORD process_id,
      DWORD thread_id,
      const TraceBasicBlockFrequencyData* data) OVERRIDE;
  // @}

 protected:
  struct PdbInfo {
    // Line and coverage information for all the source files associated with
    // a particular PDB.
    LineInfo line_info;
    // Basic-block addresses for the module associated with a particular PDB.
    // Used to transform basic-block frequency data to line visits via
    // line_info.
    RelativeAddressRangeVector bb_ranges;
  };

  typedef std::map<std::wstring, PdbInfo> PdbInfoMap;

  // Loads a new or retrieves the cached PDB info for the given PDB.
  bool GetPdbInfo(const FilePath& pdb_path, PdbInfo** pdb_info);

  // Points to the parser that is feeding us events. Used to get module
  // information.
  Parser* parser_;
  // Set to true if any call to OnBasicBlockFrequency fails. Processing will
  // continue with a warning that results may be partial.
  bool event_handler_errored_;
  // Stores per-module coverage data, populated during calls to
  // OnBasicBlockFrequency.
  PdbInfoMap pdb_info_map_;
  // Stores the final coverage data, populated by Grind. Contains an aggregate
  // of all LineInfo objects stored in the pdb_info_map_.
  LcovWriter lcov_writer_;
};

}  // namespace grinder

#endif  // SYZYGY_GRINDER_COVERAGE_GRINDER_H_

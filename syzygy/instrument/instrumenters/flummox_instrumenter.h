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
//
// Declares the flummox instrumenter.

#ifndef SYZYGY_INSTRUMENT_INSTRUMENTERS_FLUMMOX_INSTRUMENTER_H_
#define SYZYGY_INSTRUMENT_INSTRUMENTERS_FLUMMOX_INSTRUMENTER_H_

#include <memory>
#include <set>
#include <string>

#include "base/command_line.h"
#include "base/macros.h"
#include "base/files/file_path.h"
#include "syzygy/instrument/instrumenters/instrumenter_with_relinker.h"
#include "syzygy/instrument/transforms/filler_transform.h"

namespace instrument {
namespace instrumenters {

class FlummoxInstrumenter : public InstrumenterWithRelinker {
 public:
  typedef InstrumenterWithRelinker Super;

  class FlummoxConfig {
   public:
    FlummoxConfig() : add_copy_(false) { }
    ~FlummoxConfig() { }

    // Loads (from a JSON string) configurations for the flummox instrumenter.
    // The contents of the 'json' string should follow the format below:
    // {
    //   "targets": {
    //     "function_name1": [],
    //     "function_name2": [],
    //     ...
    //   },
    //   "add_copy": true|false
    // }
    // @param json A JSON string containing the configuration following the
    //     format described above.
    // @param path Path to a JSON file, to use a file instead of a string.
    // @returns True if the operation succeeded, false otherwise.
    // @{
    bool ReadFromJSON(const std::string& json);
    bool ReadFromJSONPath(const base::FilePath& path);
    // @}

    // Accessors
    // @{
    const std::set<std::string>& target_set() const { return target_set_; }
    bool add_copy() const { return add_copy_; }
    // @}

   protected:
    std::set<std::string> target_set_;
    bool add_copy_;

   private:
    DISALLOW_COPY_AND_ASSIGN(FlummoxConfig);
  };

  FlummoxInstrumenter() { }
  virtual ~FlummoxInstrumenter() { }

 protected:
  bool ParseFromJSON();

  // @name InstrumenterWithRelinker overrides.
  // @{
  bool InstrumentPrepare() override;
  bool InstrumentImpl() override;
  const char* InstrumentationMode() override { return "flummox"; }
  bool DoCommandLineParse(const base::CommandLine* command_line) override;
  // @}

  // @name Command-line parameters.
  // @{
  base::FilePath flummox_config_path_;
  // @}

  FlummoxConfig config_;

  // The main transformer.
  std::unique_ptr<instrument::transforms::FillerTransform> flummox_transform_;

 private:
  DISALLOW_COPY_AND_ASSIGN(FlummoxInstrumenter);
};

}  // namespace instrumenters
}  // namespace instrument

#endif  // SYZYGY_INSTRUMENT_INSTRUMENTERS_FLUMMOX_INSTRUMENTER_H_

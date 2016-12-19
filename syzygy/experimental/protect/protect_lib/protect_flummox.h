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

#include <set>
#include <string>

#include "base/command_line.h"
#include "base/macros.h"
#include "base/files/file_path.h"
#include "base/memory/scoped_ptr.h"
#include "syzygy/instrument/instrumenters/instrumenter_with_relinker.h"
#include "syzygy/experimental/protect/protect_lib/integrity_check_transform.h"
#include "syzygy/experimental/protect/protect_lib/integrity_check_layout_transform.h"
#include "syzygy/experimental/protect/protect_lib/protect_utils.h"

namespace protect {

typedef instrument::instrumenters::InstrumenterWithRelinker InstrumenterWithRelinker;

class CustomFlummoxInstrumenter : public InstrumenterWithRelinker {
public:
  typedef InstrumenterWithRelinker Super;

  CustomFlummoxInstrumenter() { }
  virtual ~CustomFlummoxInstrumenter() { }

 protected:
  bool ParseFromJSON();

  // @name InstrumenterWithRelinker overrides.
  // @{
  bool InstrumentPrepare() override;
  bool InstrumentImpl() override;
  const char* InstrumentationMode() override { return "protect_flummox"; }
  bool DoCommandLineParse(const base::CommandLine* command_line) override;
  // @}

  // @name Command-line parameters.
  // @{
  base::FilePath flummox_config_path_;
  // @}

  FlummoxConfig config_;

  // The main transformer.
  scoped_ptr<protect::IntegrityCheckTransform> flummox_transform_;
  scoped_ptr<protect::IntegrityCheckLayoutTransform> layout_transform_;

 private:
  DISALLOW_COPY_AND_ASSIGN(CustomFlummoxInstrumenter);
};

}  // namespace protect

#endif  // SYZYGY_INSTRUMENT_INSTRUMENTERS_FLUMMOX_INSTRUMENTER_H_
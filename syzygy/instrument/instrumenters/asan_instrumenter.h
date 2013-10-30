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
//
// Declares the Asan instrumenter.
#ifndef SYZYGY_INSTRUMENT_INSTRUMENTERS_ASAN_INSTRUMENTER_H_
#define SYZYGY_INSTRUMENT_INSTRUMENTERS_ASAN_INSTRUMENTER_H_

#include <string>

#include "base/command_line.h"
#include "syzygy/instrument/instrumenters/instrumenter_with_agent.h"
#include "syzygy/instrument/transforms/asan_transform.h"
#include "syzygy/pe/image_filter.h"
#include "syzygy/pe/pe_relinker.h"

namespace instrument {
namespace instrumenters {

class AsanInstrumenter : public InstrumenterWithAgent {
 public:
  AsanInstrumenter();

  ~AsanInstrumenter() { }

 protected:
  // The name of the agent for this mode of instrumentation.
  static const char kAgentDllAsan[];

  // @name InstrumenterWithAgent overrides.
  // @{
  virtual bool ImageFormatIsSupported(pe::ImageFormat image_format) OVERRIDE;
  virtual bool InstrumentImpl() OVERRIDE;
  virtual const char* InstrumentationMode() OVERRIDE { return "asan"; }
  virtual bool ParseAdditionalCommandLineArguments(
      const CommandLine* command_line) OVERRIDE;
  // @}

  // @name Command-line parameters.
  // @{
  base::FilePath filter_path_;
  bool use_interceptors_;
  bool remove_redundant_checks_;
  bool use_liveness_analysis_;
  // @}

  // The transform for this agent.
  scoped_ptr<instrument::transforms::AsanTransform> asan_transform_;

  // The image filter (optional).
  scoped_ptr<pe::ImageFilter> filter_;
};

}  // namespace instrumenters
}  // namespace instrument

#endif  // SYZYGY_INSTRUMENT_INSTRUMENTERS_ASAN_INSTRUMENTER_H_

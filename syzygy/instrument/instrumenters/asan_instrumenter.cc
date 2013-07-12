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

#include "syzygy/instrument/instrumenters/asan_instrumenter.h"

#include "base/file_util.h"
#include "base/logging.h"
#include "syzygy/common/application.h"
#include "syzygy/pe/image_filter.h"

namespace instrument {
namespace instrumenters {

const char AsanInstrumenter::kAgentDllAsan[] = "asan_rtl.dll";

AsanInstrumenter::AsanInstrumenter()
    : intercept_crt_functions_(false),
      remove_redundant_checks_(false),
      use_liveness_analysis_(true) {
  agent_dll_ = kAgentDllAsan;
}

bool AsanInstrumenter::InstrumentImpl() {
  // Parse the filter if one was provided.
  scoped_ptr<pe::ImageFilter> filter;
  if (!filter_path_.empty()) {
    filter.reset(new pe::ImageFilter());
    if (!filter->LoadFromJSON(filter_path_)) {
      LOG(ERROR) << "Failed to parse filter file: " << filter_path_.value();
      return false;
    }

    // Ensure it is for the input module.
    if (!filter->IsForModule(input_dll_path_)) {
      LOG(ERROR) << "Filter does not match the input module.";
      return false;
    }
  }

  asan_transform_.reset(new instrument::transforms::AsanTransform());
  asan_transform_->set_instrument_dll_name(agent_dll_);
  asan_transform_->set_intercept_crt_functions(intercept_crt_functions_);
  asan_transform_->set_use_liveness_analysis(use_liveness_analysis_);
  asan_transform_->set_remove_redundant_checks(remove_redundant_checks_);

  // Set up the filter if one was provided.
  if (filter.get())
    asan_transform_->set_filter(&filter->filter);

  // Set overwrite source range flag in the ASAN transform. The ASAN
  // transformation will overwrite the source range of created instructions to
  // the source range of corresponding instrumented instructions.
  asan_transform_->set_debug_friendly(debug_friendly_);

  relinker_->AppendTransform(asan_transform_.get());

  return true;
}

bool AsanInstrumenter::ParseAdditionalCommandLineArguments(
    const CommandLine* command_line) {
  // Parse the additional command line arguments.
  filter_path_ = command_line->GetSwitchValuePath("filter");
  use_liveness_analysis_ = !command_line->HasSwitch("no-liveness-analysis");
  remove_redundant_checks_ = command_line->HasSwitch("remove-redundant-checks");
  intercept_crt_functions_ = command_line->HasSwitch("intercept-crt-functions");

  return true;
}

}  // namespace instrumenters
}  // namespace instrument

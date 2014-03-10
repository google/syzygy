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

namespace instrument {
namespace instrumenters {

const char AsanInstrumenter::kAgentDllAsan[] = "syzyasan_rtl.dll";

AsanInstrumenter::AsanInstrumenter()
    : use_interceptors_(true),
      remove_redundant_checks_(true),
      use_liveness_analysis_(true),
      instrumentation_rate_(1.0),
      asan_rtl_options_(false) {
  agent_dll_ = kAgentDllAsan;
}

bool AsanInstrumenter::ImageFormatIsSupported(ImageFormat image_format) {
  if (image_format == BlockGraph::PE_IMAGE ||
      image_format == BlockGraph::COFF_IMAGE) {
    return true;
  }
  return false;
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
    if (!filter->IsForModule(input_image_path_)) {
      LOG(ERROR) << "Filter does not match the input module.";
      return false;
    }
  }

  asan_transform_.reset(new instrument::transforms::AsanTransform());
  asan_transform_->set_instrument_dll_name(agent_dll_);
  asan_transform_->set_use_interceptors(use_interceptors_);
  asan_transform_->set_use_liveness_analysis(use_liveness_analysis_);
  asan_transform_->set_remove_redundant_checks(remove_redundant_checks_);
  asan_transform_->set_instrumentation_rate(instrumentation_rate_);

  // Set up the filter if one was provided.
  if (filter.get()) {
    filter_.reset(filter.release());
    asan_transform_->set_filter(&filter_->filter);
  }

  // Set overwrite source range flag in the ASAN transform. The ASAN
  // transformation will overwrite the source range of created instructions to
  // the source range of corresponding instrumented instructions.
  asan_transform_->set_debug_friendly(debug_friendly_);

  // If RTL options were provided then pass them to the transform.
  if (asan_rtl_options_)
    asan_transform_->set_asan_parameters(&asan_params_);

  if (!relinker_->AppendTransform(asan_transform_.get()))
    return false;

  return true;
}

bool AsanInstrumenter::ParseAdditionalCommandLineArguments(
    const CommandLine* command_line) {
  // Parse the additional command line arguments.
  filter_path_ = command_line->GetSwitchValuePath("filter");
  use_liveness_analysis_ = !command_line->HasSwitch("no-liveness-analysis");
  remove_redundant_checks_ = !command_line->HasSwitch("no-redundancy-analysis");
  use_interceptors_ = !command_line->HasSwitch("no-interceptors");

  // Parse the instrumentation rate if one has been provided.
  static const char kInstrumentationRate[] = "instrumentation-rate";
  if (command_line->HasSwitch(kInstrumentationRate)) {
    std::string s = command_line->GetSwitchValueASCII(kInstrumentationRate);
    double d = 0;
    if (!base::StringToDouble(s, &d)) {
      LOG(ERROR) << "Failed to parse floating point value: " << s;
      return false;
    }
    // Cap the rate to the range of valid values [0, 1].
    instrumentation_rate_ = std::max(0.0, std::min(1.0, d));
  }

  // Parse ASAN RTL options if present.
  static const char kAsanRtlOptions[] = "asan-rtl-options";
  if (asan_rtl_options_ = command_line->HasSwitch(kAsanRtlOptions)) {
    std::wstring options = command_line->GetSwitchValueNative(kAsanRtlOptions);
    common::SetDefaultAsanParameters(&asan_params_);
    if (!common::ParseAsanParameters(options, &asan_params_))
      return false;
  }

  return true;
}

}  // namespace instrumenters
}  // namespace instrument

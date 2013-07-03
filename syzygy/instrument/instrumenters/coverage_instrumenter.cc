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

#include "syzygy/instrument/instrumenters/coverage_instrumenter.h"

#include "base/file_util.h"
#include "base/logging.h"
#include "syzygy/common/application.h"
#include "syzygy/pe/image_filter.h"

namespace instrument {
namespace instrumenters {

const char CoverageInstrumenter::kAgentDllCoverage[] = "coverage_client.dll";

CoverageInstrumenter::CoverageInstrumenter() {
  agent_dll_ = kAgentDllCoverage;
}

bool CoverageInstrumenter::InstrumentImpl() {
  coverage_transform_.reset(
      new instrument::transforms::CoverageInstrumentationTransform());
  coverage_transform_->set_instrument_dll_name(agent_dll_);
  coverage_transform_->set_src_ranges_for_thunks(debug_friendly_);
  relinker_->AppendTransform(coverage_transform_.get());

  add_bb_addr_stream_mutator_.reset(
        new instrument::mutators::AddIndexedDataRangesStreamPdbMutator(
            coverage_transform_->bb_ranges(),
            common::kBasicBlockRangesStreamName));
  relinker_->AppendPdbMutator(add_bb_addr_stream_mutator_.get());

  return true;
}

}  // namespace instrumenters
}  // namespace instrument

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

#include "base/logging.h"
#include "base/files/file_util.h"
#include "syzygy/application/application.h"
#include "syzygy/pe/image_filter.h"

namespace instrument {
namespace instrumenters {

const char CoverageInstrumenter::kAgentDllCoverage[] = "coverage_client.dll";

CoverageInstrumenter::CoverageInstrumenter() {
  agent_dll_ = kAgentDllCoverage;
}

bool CoverageInstrumenter::InstrumentPrepare() {
  return true;
}

bool CoverageInstrumenter::InstrumentImpl() {
  coverage_transform_.reset(
      new instrument::transforms::CoverageInstrumentationTransform());
  coverage_transform_->set_instrument_dll_name(agent_dll_);
  coverage_transform_->set_src_ranges_for_thunks(debug_friendly_);
  if (!relinker_->AppendTransform(coverage_transform_.get()))
    return false;

  add_bb_addr_stream_mutator_.reset(
        new instrument::mutators::AddIndexedDataRangesStreamPdbMutator(
            coverage_transform_->bb_ranges(),
            common::kBasicBlockRangesStreamName));
  if (!relinker_->AppendPdbMutator(add_bb_addr_stream_mutator_.get()))
    return false;

  return true;
}

}  // namespace instrumenters
}  // namespace instrument

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

#ifndef SYZYGY_REFINERY_ANALYZERS_STACK_FRAME_ANALYZER_IMPL_H_
#define SYZYGY_REFINERY_ANALYZERS_STACK_FRAME_ANALYZER_IMPL_H_

#include <dia2.h>

#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "syzygy/refinery/process_state/layer_data.h"
#include "syzygy/refinery/process_state/process_state.h"
#include "syzygy/refinery/process_state/process_state_util.h"
#include "syzygy/refinery/types/type_repository.h"

namespace refinery {

// A stack frame data analyzer analyzes data in the context of a stack frame and
// populates a process state's typed block layer with the findings.
// @note Until we move away from using DIA for stack frame symbol information,
//     this class also handles joining an IDiaSymbol to a Type via symbol name.
class StackFrameDataAnalyzer {
 public:
  StackFrameDataAnalyzer(StackFrameRecordPtr frame_record,
                         scoped_refptr<TypeNameIndex> typename_index,
                         ModuleId module_id,
                         ProcessState* process_state);

  // Analyze @p data in the context of the frame record to populate the process
  // state's typed block layer.
  // @pre data is of type SymTagData.
  // @param data the dia symbol of type SymTagData to analyze.
  // @returns true on success analysis, false otherwise.
  // @note Successful analysis does not necessarily mean modifying the process
  //     state.
  bool Analyze(IDiaSymbol* data);

 private:
  bool GetAddressRange(IDiaSymbol* data, TypePtr type, AddressRange* range);
  bool GetAddressRangeRegRel(IDiaSymbol* data,
                             TypePtr type,
                             AddressRange* range);

  StackFrameRecordPtr frame_record_;
  scoped_refptr<TypeNameIndex> typename_index_;
  ModuleId module_id_;
  // Not owned. Must outlive the StackFrameDataAnalyzer.
  ProcessState* process_state_;

  DISALLOW_COPY_AND_ASSIGN(StackFrameDataAnalyzer);
};

}  // namespace refinery

#endif  // SYZYGY_REFINERY_ANALYZERS_STACK_FRAME_ANALYZER_IMPL_H_

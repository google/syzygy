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

#ifndef SYZYGY_REFINERY_PROCESS_STATE_PROCESS_STATE_UTIL_H_
#define SYZYGY_REFINERY_PROCESS_STATE_PROCESS_STATE_UTIL_H_

#include <string>

#include "base/strings/string_piece.h"
#include "syzygy/refinery/core/address.h"
#include "syzygy/refinery/process_state/process_state.h"
#include "syzygy/refinery/process_state/refinery.pb.h"

namespace refinery {

using BytesLayerPtr = scoped_refptr<ProcessState::Layer<Bytes>>;
using BytesRecordPtr = ProcessState::Layer<Bytes>::RecordPtr;

using StackLayerPtr = scoped_refptr<ProcessState::Layer<Stack>>;
using StackRecordPtr = ProcessState::Layer<Stack>::RecordPtr;

using StackFrameLayerPtr = scoped_refptr<ProcessState::Layer<StackFrame>>;
using StackFrameRecordPtr = ProcessState::Layer<StackFrame>::RecordPtr;

using TypedBlockLayerPtr = scoped_refptr<ProcessState::Layer<TypedBlock>>;
using TypedBlockRecordPtr = ProcessState::Layer<TypedBlock>::RecordPtr;

using ModuleLayerPtr = scoped_refptr<ProcessState::Layer<Module>>;
using ModuleRecordPtr = ProcessState::Layer<Module>::RecordPtr;

void AddModuleRecord(const AddressRange& range,
                     const uint32 checksum,
                     const uint32 timestamp,
                     const std::string& path,
                     ProcessState* process_state);

bool AddTypedBlockRecord(const AddressRange& range,
                         base::StringPiece16 data_name,
                         base::StringPiece16 type_name,
                         ProcessState* process_state);

}  // namespace refinery

#endif  // SYZYGY_REFINERY_PROCESS_STATE_PROCESS_STATE_UTIL_H_

// Copyright 2017 Google Inc. All Rights Reserved.
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
// This transform redirects the '__report_gsfailure' function to
// the following assembly stub: 'mov [deadbeef], 0'.
// The function __report_gsfailure raises an exception that an EH
// cannot intercept (for security reasons); this transform allows
// an EH to catch the GS failures.

#ifndef SYZYGY_INSTRUMENT_TRANSFORMS_SECURITY_COOKIE_CHECK_HOOK_TRANSFORM_H_
#define SYZYGY_INSTRUMENT_TRANSFORMS_SECURITY_COOKIE_CHECK_HOOK_TRANSFORM_H_

#include "base/logging.h"
#include "syzygy/block_graph/basic_block_assembler.h"
#include "syzygy/block_graph/basic_block_subgraph.h"
#include "syzygy/block_graph/block_builder.h"
#include "syzygy/block_graph/transform_policy.h"
#include "syzygy/block_graph/transforms/named_transform.h"

namespace instrument {
namespace transforms {

typedef block_graph::BasicBlockAssembler BasicBlockAssembler;
typedef block_graph::BasicBlockSubGraph BasicBlockSubGraph;
typedef block_graph::BasicCodeBlock BasicCodeBlock;
typedef block_graph::BlockGraph BlockGraph;
typedef block_graph::BlockBuilder BlockBuilder;
typedef block_graph::TransformPolicyInterface TransformPolicyInterface;

class SecurityCookieCheckHookTransform
    : public block_graph::transforms::NamedBlockGraphTransformImpl<
          SecurityCookieCheckHookTransform> {
 public:
  SecurityCookieCheckHookTransform() {}

  static const char kTransformName[];
  static const char kReportGsFailure[];
  static const char kSyzygyReportGsFailure[];
  static const uint32_t kInvalidUserAddress;

  // BlockGraphTransformInterface implementation.
  bool TransformBlockGraph(const TransformPolicyInterface* policy,
                           BlockGraph* block_graph,
                           BlockGraph::Block* header_block) final;
};

}  // namespace transforms
}  // namespace instrument

#endif  // SYZYGY_INSTRUMENT_TRANSFORMS_SECURITY_COOKIE_CHECK_HOOK_TRANSFORM_H_

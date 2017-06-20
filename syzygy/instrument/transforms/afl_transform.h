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
// This transforms statically instruments code blocks with an AFL
// instrumentation.
// An instrumented binary can then be fuzzed via WinAFL which implements
// the 'runtime' support.
//
// For more information about AFL & WinAFL, technical details can be found here:
// http://lcamtuf.coredump.cx/afl/technical_details.txt and here:
// https://github.com/ivanfratric/winafl.

#ifndef SYZYGY_INSTRUMENT_TRANSFORMS_AFL_TRANSFORM_H_
#define SYZYGY_INSTRUMENT_TRANSFORMS_AFL_TRANSFORM_H_

#include "base/logging.h"
#include "syzygy/block_graph/basic_block_assembler.h"
#include "syzygy/block_graph/basic_block_subgraph.h"
#include "syzygy/block_graph/block_builder.h"
#include "syzygy/block_graph/transform_policy.h"
#include "syzygy/block_graph/transforms/iterative_transform.h"
#include "syzygy/block_graph/transforms/named_transform.h"

namespace instrument {
namespace transforms {

typedef block_graph::BasicBlock BasicBlock;
typedef block_graph::BasicBlockAssembler BasicBlockAssembler;
typedef block_graph::BasicBlockSubGraph BasicBlockSubGraph;
typedef block_graph::BasicCodeBlock BasicCodeBlock;
typedef block_graph::BlockGraph BlockGraph;
typedef core::RelativeAddress RelativeAddress;
typedef core::AddressRange<RelativeAddress, size_t> RelativeAddressRange;
typedef std::vector<RelativeAddressRange> RelativeAddressRangeVector;
typedef block_graph::TransformPolicyInterface TransformPolicyInterface;

class AFLTransform
    : public block_graph::transforms::IterativeTransformImpl<AFLTransform>,
      public block_graph::transforms::NamedBasicBlockSubGraphTransformImpl<
          AFLTransform> {
 public:
  // This transform instruments the graph with the AFL instrumentation.
  // The instrumentation has been designed to support a whitelist/blacklist
  // mode in case the instrumentation should be scoped. The targets set
  // contains substrings that will be used to match the function names of
  // the graph. Note that the targets set cannot be empty when using
  // either of the scoping mode (see 'targets_visited_' and 'whitelist_mode_').
  // The user can force the decomposition and ignore what the
  // 'BlockIsSafeToBasicBlockDecompose' policy says (see 'force_decompose_').
  // There are two flavors of instrumentation available: one thread-safe,
  // and one that is not (see 'multithread_').
  // The transform can also leverage the 'SecurityCookieCheckHook' transform,
  // in order to have /GS cookie exception 'catchable' by an in-proc exception
  // handler.
  AFLTransform(const std::unordered_set<std::string>& targets,
               bool whitelist_mode,
               bool force_decompose,
               bool multithread,
               bool cookie_check_hook)
      : tls_afl_prev_loc_displacement_(0),
        whitelist_mode_(whitelist_mode),
        force_decompose_(force_decompose),
        multithread_(multithread),
        cookie_check_hook_(cookie_check_hook),
        total_blocks_(0),
        total_code_blocks_(0),
        total_code_blocks_instrumented_(0) {
    for (const auto& target : targets) {
      targets_visited_.emplace(target, 0);
    }
  }

  static const char kTransformName[];
  static const char kSectionName[];
  static const char kMetadataBlockName[];
  static const size_t kOffsetTebStorage;

  // The below offsets are needed by both the transform itself, and its
  // associated tests. That is the reason why they are visible here.
  // They also hide the definition of the underlying structure.
  static const size_t kOffsetArea;
  static const size_t kOffsetAreaPtr;
  static const size_t kOffsetPrevLoc;
  static const size_t kOffsetTlsIndex;

  // Functions needed for IterativeTransform.
  bool PreBlockGraphIteration(const TransformPolicyInterface* policy,
                              BlockGraph* block_graph,
                              BlockGraph::Block* header_block);

  bool OnBlock(const TransformPolicyInterface* policy,
               BlockGraph* block_graph,
               BlockGraph::Block* block);

  bool PostBlockGraphIteration(const TransformPolicyInterface* policy,
                               BlockGraph* block_graph,
                               BlockGraph::Block* header_block);

  // Function needed for NamedBasicBlockSubGraphTransformImpl.
  bool TransformBasicBlockSubGraph(
      const TransformPolicyInterface* policy,
      BlockGraph* block_graph,
      BasicBlockSubGraph* basic_block_subgraph) final;

  const RelativeAddressRangeVector& bb_ranges() { return bb_ranges_; }

 protected:
  // Basic-block instrumentation related functions.
  bool ShouldInstrumentBlock(BlockGraph::Block* block);
  void instrument(BasicBlockAssembler& assm, size_t cur_loc);

  // The data-block that keeps the metadata regarding the instrumentation.
  BlockGraph::Block* afl_static_cov_data_;

  // This is the offset from the TLS memory where the __afl_prev_loc slot has
  // been placed.
  size_t tls_afl_prev_loc_displacement_;

  // The RVAs in the original image for each instrumented basic block.
  RelativeAddressRangeVector bb_ranges_;

  // A map keeping track of the pattern that should get black/whitelisted.
  // The integer is the number of times the pattern matched.
  std::map<std::string, size_t> targets_visited_;

  // Various configuration switches coming from the command line.
  bool whitelist_mode_;
  bool force_decompose_;
  bool multithread_;
  bool cookie_check_hook_;

  // Stats.
  size_t total_blocks_;
  size_t total_code_blocks_;
  size_t total_code_blocks_instrumented_;
};

}  // namespace transforms
}  // namespace instrument

#endif  // SYZYGY_INSTRUMENT_TRANSFORMS_AFL_TRANSFORM_H_

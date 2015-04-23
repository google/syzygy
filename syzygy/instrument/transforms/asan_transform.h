// Copyright 2012 Google Inc. All Rights Reserved.
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
// Implementation of the SyzyAsan instrumentation transform.

#ifndef SYZYGY_INSTRUMENT_TRANSFORMS_ASAN_TRANSFORM_H_
#define SYZYGY_INSTRUMENT_TRANSFORMS_ASAN_TRANSFORM_H_

#include <map>
#include <set>
#include <string>
#include <utility>

#include "base/strings/string_piece.h"
#include "syzygy/block_graph/filterable.h"
#include "syzygy/block_graph/iterate.h"
#include "syzygy/block_graph/analysis/liveness_analysis.h"
#include "syzygy/block_graph/analysis/memory_access_analysis.h"
#include "syzygy/block_graph/transforms/iterative_transform.h"
#include "syzygy/block_graph/transforms/named_transform.h"
#include "syzygy/common/asan_parameters.h"
#include "syzygy/instrument/transforms/asan_interceptor_filter.h"
#include "syzygy/instrument/transforms/asan_intercepts.h"

namespace instrument {
namespace transforms {

// This class implements the transformation applied to each basic block.
class AsanBasicBlockTransform
    : public block_graph::transforms::NamedBasicBlockSubGraphTransformImpl<
          AsanBasicBlockTransform>,
      public block_graph::Filterable {
 public:
  // Represent the different kind of access to the memory.
  enum MemoryAccessMode {
    kNoAccess,
    kReadAccess,
    kWriteAccess,
    kInstrAccess,
    kRepzAccess,
    kRepnzAccess,
  };

  enum StackAccessMode {
    kUnsafeStackAccess,
    kSafeStackAccess,
  };

  // Contains memory access information.
  struct MemoryAccessInfo {
    MemoryAccessMode mode;
    uint8_t size;
    uint16_t opcode;
    // True iff we need to save the flags for this access.
    bool save_flags;
  };

  typedef block_graph::BlockGraph BlockGraph;
  typedef block_graph::BasicBlockSubGraph BasicBlockSubGraph;
  typedef block_graph::TransformPolicyInterface TransformPolicyInterface;
  typedef MemoryAccessInfo AsanHookMapEntryKey;
  // Map of hooks to Asan check access functions.
  typedef std::map<AsanHookMapEntryKey, BlockGraph::Reference> AsanHookMap;
  typedef std::map<MemoryAccessMode, BlockGraph::Reference> AsanDefaultHookMap;

  // Constructor.
  // @param check_access_hooks References to the various check access functions.
  //     The hooks are assumed to be direct references for COFF images, and
  //     indirect references for PE images.
  explicit AsanBasicBlockTransform(AsanHookMap* check_access_hooks) :
      check_access_hooks_(check_access_hooks),
      debug_friendly_(false),
      dry_run_(false),
      instrumentation_happened_(false),
      instrumentation_rate_(1.0),
      remove_redundant_checks_(false),
      use_liveness_analysis_(false) {
    DCHECK(check_access_hooks != NULL);
  }

  // @name Accessors and mutators.
  // @{
  bool debug_friendly() const { return debug_friendly_; }
  void set_debug_friendly(bool flag) { debug_friendly_ = flag; }

  bool use_liveness_analysis() { return use_liveness_analysis_; }
  void set_use_liveness_analysis(bool use_liveness_analysis) {
    use_liveness_analysis_ = use_liveness_analysis;
  }

  bool remove_redundant_checks() const { return remove_redundant_checks_; }
  void set_remove_redundant_checks(bool remove_redundant_checks) {
    remove_redundant_checks_ = remove_redundant_checks;
  }

  // The instrumentation rate must be in the range [0, 1], inclusive.
  double instrumentation_rate() const { return instrumentation_rate_; }
  void set_instrumentation_rate(double instrumentation_rate);

  // Instead of instrumenting the basic blocks, in dry run mode the instrumenter
  // only signals if any instrumentation would have happened on the block.
  // @returns true iff the instrumenter is in dry run mode.
  bool dry_run() const { return dry_run_; }
  // Instead of instrumenting the basic blocks, in dry run mode the instrumenter
  // only signals if any instrumentation would have happened on the block.
  // @param dry_run true iff dry run mode is on.
  void set_dry_run(bool dry_run) { dry_run_ = dry_run; }

  // If at least one instrumentation happened during a transform, or would have
  // happened during a dry run transform, this returns true.
  // @returns true iff an instrumentation happened (or would have happened, in
  //     case of a dry run).
  bool instrumentation_happened() const { return instrumentation_happened_; }
  // @}

  // The transform name.
  static const char kTransformName[];

  // @name BasicBlockSubGraphTransformInterface method.
  virtual bool TransformBasicBlockSubGraph(
      const TransformPolicyInterface* policy,
      BlockGraph* block_graph,
      BasicBlockSubGraph* basic_block_subgraph) override;

 protected:
  // Instruments the memory accesses in a basic block.
  // @param basic_block The basic block to be instrumented.
  // @param stack_mode Give some assumptions to the transformation on stack
  //     frame manipulations inside @p basic_block. The transformation assume a
  //     standard calling convention, unless specified by this parameter.
  //     (note: Unsafe blocks may be produced with the compiler flag
  //     frame-pointer-omission).
  // @param image_format The format of the image being instrumented. The details
  //     of how we invoke the hooks vary depending on this.
  // @returns true on success, false otherwise.
  bool InstrumentBasicBlock(block_graph::BasicCodeBlock* basic_block,
                            StackAccessMode stack_mode,
                            BlockGraph::ImageFormat image_format);

 private:
  // Liveness analysis and liveness information for this subgraph.
  block_graph::analysis::LivenessAnalysis liveness_;

  // Memory accesses value numbering.
  block_graph::analysis::MemoryAccessAnalysis memory_accesses_;

  // The references to the Asan access check import entries.
  AsanHookMap* check_access_hooks_;

  // Activate the overwriting of source range for created instructions.
  bool debug_friendly_;

  // Instead of instrumenting the basic blocks, run in dry run mode and just
  // signal whether there would be an instrumentation in the block.
  bool dry_run_;

  // Controls the rate at which reads/writes are instrumented. This is
  // implemented using random sampling.
  double instrumentation_rate_;

  // If any instrumentation happened during a transform, or would have happened
  // during a dry run transform, this member is set to true.
  bool instrumentation_happened_;

  // When activated, a redundancy elimination is performed to minimize the
  // memory checks added by this transform.
  bool remove_redundant_checks_;

  // Set iff we should use the liveness analysis to do smarter instrumentation.
  bool use_liveness_analysis_;

  DISALLOW_COPY_AND_ASSIGN(AsanBasicBlockTransform);
};

// This runs Asan basic block transform in dry run mode and prepares the block
// for hot patching if Asan would instrument it. Doing these two things in a
// single basic block transform avoids running basic block decomposer twice.
class HotPatchingAsanBasicBlockTransform
    : public block_graph::transforms::NamedBasicBlockSubGraphTransformImpl<
          AsanBasicBlockTransform>,
      public block_graph::Filterable {
 public:
  typedef block_graph::BlockGraph BlockGraph;
  typedef block_graph::BasicBlockSubGraph BasicBlockSubGraph;
  typedef block_graph::TransformPolicyInterface TransformPolicyInterface;

  // Construct a HotPatchingAsanBasicBlockTransform.
  // @param asan_bb_transform An Asan basic block transform that will be run
  //     to check if an instrumentation would happen.
  // @pre the transform in the parameter must be in dry run mode.
  HotPatchingAsanBasicBlockTransform(
      AsanBasicBlockTransform* asan_bb_transform);

  // @name BasicBlockSubGraphTransformInterface method.
  virtual bool TransformBasicBlockSubGraph(
      const TransformPolicyInterface* policy,
      BlockGraph* block_graph,
      BasicBlockSubGraph* basic_block_subgraph) override;

  // Check if the block in the subgraph was prepared for hot patching during
  // the last run of TransformBasicBlockSubGraph.
  // @returns true if the prepared the block for hot patching, false if the
  //     block needs no Asan instrumentation.
  bool prepared_for_hot_patching() {
    return prepared_for_hot_patching_;
  }

 private:
  AsanBasicBlockTransform* asan_bb_transform_;

  bool prepared_for_hot_patching_;
};

class AsanTransform
    : public block_graph::transforms::IterativeTransformImpl<AsanTransform>,
      public block_graph::Filterable {
 public:
  typedef block_graph::BlockGraph BlockGraph;
  typedef block_graph::TransformPolicyInterface TransformPolicyInterface;
  typedef AsanBasicBlockTransform::MemoryAccessMode MemoryAccessMode;
  typedef std::set<BlockGraph::Block*, BlockGraph::BlockIdLess> BlockSet;

  // Initialize a new AsanTransform instance.
  AsanTransform();

  ~AsanTransform();

  // @name IterativeTransformImpl implementation.
  // @{
  bool PreBlockGraphIteration(const TransformPolicyInterface* policy,
                              BlockGraph* block_graph,
                              BlockGraph::Block* header_block);
  bool OnBlock(const TransformPolicyInterface* policy,
               BlockGraph* block_graph,
               BlockGraph::Block* block);
  bool PostBlockGraphIteration(const TransformPolicyInterface* policy,
                               BlockGraph* block_graph,
                               BlockGraph::Block* header_block);
  // @}

  // @name Accessors and mutators.
  // @{
  void set_instrument_dll_name(const base::StringPiece& instrument_dll_name) {
    instrument_dll_name.CopyToString(&asan_dll_name_);
  }
  // Name of the asan_rtl DLL we import. The |instrument_dll_name_| member is
  // empty by default, in that case |kSyzyAsanDll| will be returned if hot
  // patching mode is disabled and |kSyzyAsanHpDll| will be returned in hot
  // patching mode.
  // @returns the name of the runtime library of the instrumentation.
  base::StringPiece instrument_dll_name() const;

  bool debug_friendly() const { return debug_friendly_; }
  void set_debug_friendly(bool flag) { debug_friendly_ = flag; }

  bool use_interceptors() const { return use_interceptors_; }
  void set_use_interceptors(bool use_interceptors) {
    use_interceptors_ = use_interceptors;
  }

  bool use_liveness_analysis() const { return use_liveness_analysis_; }
  void set_use_liveness_analysis(bool use_liveness_analysis) {
    use_liveness_analysis_ = use_liveness_analysis;
  }

  bool remove_redundant_checks() const { return remove_redundant_checks_; }
  void set_remove_redundant_checks(bool remove_redundant_checks) {
    remove_redundant_checks_ = remove_redundant_checks;
  }

  // The instrumentation rate must be in the range [0, 1], inclusive.
  double instrumentation_rate() const { return instrumentation_rate_; }
  void set_instrumentation_rate(double instrumentation_rate);

  // Asan RTL parameters.
  const common::InflatedAsanParameters* asan_parameters() const {
    return asan_parameters_;
  }
  void set_asan_parameters(
      const common::InflatedAsanParameters* asan_parameters) {
    asan_parameters_ = asan_parameters;
  }
  // @}

  // Checks if the transform is in hot patching mode.
  // @returns true iff in hot patching mode.
  bool hot_patching() const {
    return hot_patching_;
  }
  // If this flag is true, running the transformation prepares the module to
  // be used by the hot patching Asan runtime.
  // @param hot_patching The new value of the flag.
  void set_hot_patching(bool hot_patching) {
    hot_patching_ = hot_patching;
  }

  // The name of the DLL that is imported by default if hot patching mode is
  // inactive.
  static const char kSyzyAsanDll[];

  // The name of the DLL that is imported by default in hot patching mode.
  static const char kSyzyAsanHpDll[];

  // The transform name.
  static const char kTransformName[];

  // The hooks stub name.
  static const char kAsanHookStubName[];

 protected:
  // PreBlockGraphIteration uses this to find the block of the _heap_init
  // function and the data block of _crtheap. This information is used by
  // PatchCRTHeapInitialization. Also, the block of _heap_init is skipped by
  // OnBlock.
  // Calling this initializes heap_init_block_ and crtheap_block_ members.
  // @param block_graph The block graph to be searched.
  // @pre Both heap_init_block_ and crtheap_block_ must be nullptr.
  // @note If either heap_init_block_ and crtheap_block_ is not found, both are
  //     set to nullptr.
  void FindHeapInitAndCrtHeapBlocks(BlockGraph* block_graph);

  // Decides if we should skip a Block in OnBlock. A block is skipped if
  // either
  //   - it is the block of _heap_init,
  //   - it is in the static_intercepted_blocks_ set,
  //   - it is not safe to BB-decompose.
  // @param policy The policy object that tells if a block is safe to
  //     BB-decompose.
  // @param block The block to examine.
  // @returns true iff the block should be skipped.
  bool ShouldSkipBlock(const TransformPolicyInterface* policy,
                       BlockGraph::Block* block);

  // @name PE-specific methods.
  // @{
  // Finds statically linked functions that need to be intercepted. Called in
  // PreBlockGraphTransform. Fills the static_intercepted_blocks_ set.
  // Blocks in this set are skipped in OnBlock and intercepted in
  // PeInterceptFunctions.
  // @param intercepts The Asan intercepts.
  // @param block_graph The block graph to search in.
  void PeFindStaticallyLinkedFunctionsToIntercept(
      const AsanIntercept* intercepts,
      BlockGraph* block_graph);

  // Invoked when instrumenting a PE image. Intercepts all relevant import
  // and statically linked functions found in the image. The intercepts to be
  // used are exposed for unittesting.
  bool PeInterceptFunctions(const AsanIntercept* intercepts,
                            const TransformPolicyInterface* policy,
                            BlockGraph* block_graph,
                            BlockGraph::Block* header_block);

  // Injects runtime parameters into the image.
  bool PeInjectAsanParameters(const TransformPolicyInterface* policy,
                              BlockGraph* block_graph,
                              BlockGraph::Block* header_block);
  // @}

  // @name COFF-specific methods.
  // @{
  // Invoked when instrumenting a COFF image. Intercepts all relevant functions
  // via symbol renaming, redirecting to Asan instrumented versions. The
  // intercepts to be used are exposed for unittesting.
  bool CoffInterceptFunctions(const AsanIntercept* intercepts,
                              const TransformPolicyInterface* policy,
                              BlockGraph* block_graph,
                              BlockGraph::Block* header_block);
  // @}

  // Name of the asan_rtl DLL we import. Do not access this directly, use the
  // instrument_dll_name() getter that provides default values.
  std::string asan_dll_name_;

  // Activate the overwriting of source range for created instructions.
  bool debug_friendly_;

  // Set iff we should use the liveness analysis to do smarter instrumentation.
  bool use_liveness_analysis_;

  // When activated, a redundancy elimination is performed to minimize the
  // memory checks added by this transform.
  bool remove_redundant_checks_;

  // Set iff we should use the functions interceptors.
  bool use_interceptors_;

  // Controls the rate at which reads/writes are instrumented. This is
  // implemented using random sampling.
  double instrumentation_rate_;

  // Asan RTL parameters that will be injected into the instrumented image.
  // These will be found by the RTL and used to control its behaviour. Allows
  // for setting parameters at instrumentation time that vary from the defaults.
  // These can still be overridden by configuring the RTL via an environment
  // variable.
  const common::InflatedAsanParameters* asan_parameters_;

  // References to the different Asan check access import entries. Valid after
  // successful PreBlockGraphIteration.
  AsanBasicBlockTransform::AsanHookMap check_access_hooks_ref_;

  // Block containing any injected runtime parameters. Valid in PE mode after
  // a successful PostBlockGraphIteration. This is a unittesting seam.
  block_graph::BlockGraph::Block* asan_parameters_block_;

  // Pointers to the heap initialization block and the block of the CRT heap
  // pointer. These are determined during PreBlockGraphIteration, and are either
  // both present or both nullptr. The heap initialization block is skipped
  // during OnBlock, then transformed in PostBlockGraphIteration
  // (via PatchCRTHeapInitialization). The block of the CRT heap pointer
  // is needed for this transformation.
  BlockGraph::Block* heap_init_block_;
  BlockGraph::Block* crtheap_block_;

  // Statically linked functions that need to be intercepted. Populated by
  // PeFindStaticallyLinkedFunctionsToIntercept. Block in this set are skipped
  // in OnBlock and intercepted in PeInterceptFunctions.
  // This is a set because OnBlock needs fast lookup. We sort by the BlockID
  // to have a consistent output in PeInterceptFunctions.
  BlockSet static_intercepted_blocks_;

  // If this flag is true, running the transformation prepares the module to
  // be used by the hot patching Asan runtime.
  bool hot_patching_;

  // In hot patching mode, this vector is used to collect the blocks prepared
  // for hot patching in the OnBlock method and insert them to the hot patching
  // metadata stream in the PostBlockGraphIteration.
  std::vector<BlockGraph::Block*> hot_patched_blocks_;

 private:
  DISALLOW_COPY_AND_ASSIGN(AsanTransform);
};

bool operator<(const AsanBasicBlockTransform::MemoryAccessInfo& left,
               const AsanBasicBlockTransform::MemoryAccessInfo& right);

}  // namespace transforms
}  // namespace instrument

#endif  // SYZYGY_INSTRUMENT_TRANSFORMS_ASAN_TRANSFORM_H_

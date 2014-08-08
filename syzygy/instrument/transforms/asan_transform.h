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
  // Map of hooks to asan check access functions.
  typedef std::map<AsanHookMapEntryKey, BlockGraph::Reference> AsanHookMap;
  typedef std::map<MemoryAccessMode, BlockGraph::Reference> AsanDefaultHookMap;

  // Constructor.
  // @param check_access_hooks References to the various check access functions.
  //     The hooks are assumed to be direct references for COFF images, and
  //     indirect references for PE images.
  explicit AsanBasicBlockTransform(AsanHookMap* check_access_hooks) :
      check_access_hooks_(check_access_hooks),
      debug_friendly_(false),
      use_liveness_analysis_(false),
      remove_redundant_checks_(false),
      instrumentation_rate_(1.0) {
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
  // @}

  // The transform name.
  static const char kTransformName[];

 protected:
  // @name BasicBlockSubGraphTransformInterface method.
  virtual bool TransformBasicBlockSubGraph(
      const TransformPolicyInterface* policy,
      BlockGraph* block_graph,
      BasicBlockSubGraph* basic_block_subgraph) OVERRIDE;

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

  // Set iff we should use the liveness analysis to do smarter instrumentation.
  bool use_liveness_analysis_;

  // When activated, a redundancy elimination is performed to minimize the
  // memory checks added by this transform.
  bool remove_redundant_checks_;

  // Controls the rate at which reads/writes are instrumented. This is
  // implemented using random sampling.
  double instrumentation_rate_;

  DISALLOW_COPY_AND_ASSIGN(AsanBasicBlockTransform);
};

class AsanTransform
    : public block_graph::transforms::IterativeTransformImpl<AsanTransform>,
      public block_graph::Filterable {
 public:
  typedef block_graph::BlockGraph BlockGraph;
  typedef block_graph::TransformPolicyInterface TransformPolicyInterface;
  typedef AsanBasicBlockTransform::MemoryAccessInfo MemoryAccessInfo;
  typedef AsanBasicBlockTransform::MemoryAccessMode MemoryAccessMode;

  // Initialize a new AsanTransform instance.
  AsanTransform();

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
  const char* instrument_dll_name() const {
    return asan_dll_name_.c_str();
  }

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

  // ASAN RTL parameters.
  const common::InflatedAsanParameters* asan_parameters() const {
    return asan_parameters_;
  }
  void set_asan_parameters(
      const common::InflatedAsanParameters* asan_parameters) {
    asan_parameters_ = asan_parameters;
  }
  // @}

  // The name of the DLL that is imported by default.
  static const char kSyzyAsanDll[];

  // The transform name.
  static const char kTransformName[];

  // The hooks stub name.
  static const char kAsanHookStubName[];

 protected:
  // @name PE-specific methods.
  // @{
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
  // via symbol renaming, redirecting to ASAN instrumented versions. The
  // intercepts to be used are exposed for unittesting.
  bool CoffInterceptFunctions(const AsanIntercept* intercepts,
                              const TransformPolicyInterface* policy,
                              BlockGraph* block_graph,
                              BlockGraph::Block* header_block);
  // @}

  // Name of the asan_rtl DLL we import. Defaults to "syzyasan_rtl.dll".
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

  // ASAN RTL parameters that will be injected into the instrumented image.
  // These will be found by the RTL and used to control its behaviour. Allows
  // for setting parameters at instrumentation time that vary from the defaults.
  // These can still be overridden by configuring the RTL via an environment
  // variable.
  const common::InflatedAsanParameters* asan_parameters_;

  // References to the different asan check access import entries. Valid after
  // successful PreBlockGraphIteration.
  AsanBasicBlockTransform::AsanHookMap check_access_hooks_ref_;

  // Block containing any injected runtime parameters. Valid in PE mode after
  // a successful PostBlockGraphIteration. This is a unittesting seam.
  block_graph::BlockGraph::Block* asan_parameters_block_;

 private:
  DISALLOW_COPY_AND_ASSIGN(AsanTransform);
};

bool operator<(const AsanBasicBlockTransform::MemoryAccessInfo& left,
               const AsanBasicBlockTransform::MemoryAccessInfo& right);

}  // namespace transforms
}  // namespace instrument

#endif  // SYZYGY_INSTRUMENT_TRANSFORMS_ASAN_TRANSFORM_H_

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

#include "syzygy/instrument/transforms/afl_transform.h"

#include <algorithm>
#include <random>

#include "syzygy/block_graph/block_util.h"
#include "syzygy/block_graph/typed_block.h"
#include "syzygy/instrument/transforms/add_implicit_tls_transform.h"
#include "syzygy/instrument/transforms/security_cookie_check_hook_transform.h"
#include "syzygy/pe/pe_utils.h"

// Abstract a PRNG and minimize re-use of the randomized integers in
// [0 .. 'upper_bound'[.
class RandomCtr {
 public:
  explicit RandomCtr(const size_t upper_bound) : idx_(0) {
    for (size_t i = 0; i < upper_bound; ++i) {
      numbers_.push_back(i);
    }

    std::random_device rd;
    std::mt19937 g(rd());
    std::shuffle(numbers_.begin(), numbers_.end(), g);
  }

  size_t next() { return numbers_[idx_++ % numbers_.size()]; }

 private:
  std::vector<size_t> numbers_;
  size_t idx_;
};

namespace instrument {
namespace transforms {

static const size_t kMapSize = 1 << 16;

#pragma pack(push, 1)

// Describe the layout of the '.syzyafl' section.
struct StaticCoverageData {
  uint32_t tls_index;
  uint32_t tls_slot_offset;
  uint32_t* afl_prev_loc;
  uint8_t* afl_area_ptr;
  uint8_t afl_area[kMapSize];
};

#pragma pack(pop)

using block_graph::Displacement;
using block_graph::Operand;
using block_graph::Immediate;

const char AFLTransform::kTransformName[] = "AFLTransform";
const char AFLTransform::kSectionName[] = ".syzyafl";
const char AFLTransform::kMetadataBlockName[] = "__afl_static_cov_data";
// 0:000> dt ntdll!_TEB ThreadLocalStoragePointer
//   +0x02c ThreadLocalStoragePointer : Ptr32 Void
const size_t AFLTransform::kOffsetTebStorage = 0x2C;
const size_t AFLTransform::kOffsetArea = offsetof(StaticCoverageData, afl_area);
const size_t AFLTransform::kOffsetAreaPtr =
    offsetof(StaticCoverageData, afl_area_ptr);
const size_t AFLTransform::kOffsetPrevLoc =
    offsetof(StaticCoverageData, afl_prev_loc);
const size_t AFLTransform::kOffsetTlsIndex =
    offsetof(StaticCoverageData, tls_index);

bool AFLTransform::PreBlockGraphIteration(
    const TransformPolicyInterface* policy,
    BlockGraph* block_graph,
    BlockGraph::Block* header_block) {
  // Create the '.syzyafl' section to store our medatada.
  BlockGraph::Section* section = block_graph->FindOrAddSection(
      kSectionName, pe::kReadWriteDataCharacteristics);

  if (section == nullptr) {
    LOG(ERROR) << "Failed to add the " << kSectionName << " section.";
    return false;
  }

  afl_static_cov_data_ = block_graph->AddBlock(
      BlockGraph::DATA_BLOCK, sizeof(StaticCoverageData), kMetadataBlockName);

  if (afl_static_cov_data_ == nullptr) {
    LOG(ERROR) << "Failed to add the " << kMetadataBlockName << " block.";
    return false;
  }

  afl_static_cov_data_->set_section(section->id());

  // We are saving space on disk by only allocating the first part of the
  // structure.
  // Only this part will be backed on disk, the rest will only exist in memory.
  StaticCoverageData* static_cov_data = reinterpret_cast<StaticCoverageData*>(
      afl_static_cov_data_->AllocateData(kOffsetArea));

  // Initialize afl_area_ptr with a pointer to the coverage bitmap embedded in
  // the binary (this ensures the target can run without runtime patching).
  afl_static_cov_data_->SetReference(
      kOffsetAreaPtr,
      BlockGraph::Reference(BlockGraph::ABSOLUTE_REF,
                            BlockGraph::Reference::kMaximumSize,
                            afl_static_cov_data_, kOffsetArea, 0));

  if (cookie_check_hook_) {
    // Hook __security_cookie_check if asked by the user.
    SecurityCookieCheckHookTransform cookie_hook;
    if (!ApplyBlockGraphTransform(&cookie_hook, policy, block_graph,
                                  header_block)) {
      LOG(WARNING) << "The SecurityCookieCheckHookTransform transform failed.";
    }
  }

  if (multithread_) {
    // If we have the multithread enabled, the 'afl_prev_loc' variable is stored
    // in an implicit TLS slot.
    AddImplicitTlsTransform afl_prev_loc_tls(afl_static_cov_data_,
                                             kOffsetTlsIndex);

    if (!ApplyBlockGraphTransform(&afl_prev_loc_tls, policy, block_graph,
                                  header_block)) {
      LOG(ERROR) << "The AddImplicitTlsTransform transform failed.";
      return false;
    }

    // The displacement is necessary to generate the proper instrumentation
    // later.
    tls_afl_prev_loc_displacement_ = afl_prev_loc_tls.tls_displacement();
    LOG(INFO) << "Placing TLS slot at offset +"
              << tls_afl_prev_loc_displacement_ << ".";
  }

  // Store the implicit TLS slot offset inside the '.syzyafl' section.
  static_cov_data->tls_slot_offset = tls_afl_prev_loc_displacement_;
  return true;
}

bool AFLTransform::ShouldInstrumentBlock(BlockGraph::Block* block) {
  bool should_instrument = true;
  std::string name(block->name());

  // We are ignoring every functions prefixed by __afl (the set-up functions,
  // the persitent loop implementation, the veh handler, etc).
  if (!name.compare(0, 5, "__afl")) {
    return false;
  }

  // Check if we are in whitelist or blacklist mode.
  // Note that the instrumenter makes sure the set cannot be empty when
  // using either of the whitelist or blacklist mode.
  if (targets_visited_.size() != 0) {
    bool found_match = false;
    for (auto& target : targets_visited_) {
      found_match = name.find(target.first) != std::string::npos;
      if (found_match) {
        target.second++;
        break;
      }
    }

    // In blacklist mode: if we find a match it means that
    // this is a block we don't want to instrument.
    if (found_match && !whitelist_mode_) {
      should_instrument = false;
    }

    // In whitelist mode: not finding a match means we shouldn't
    // instrument this block.
    if (!found_match && whitelist_mode_) {
      should_instrument = false;
    }
  }

  if (should_instrument && name != "") {
    VLOG(1) << "Instrumenting " << name;
  }

  return should_instrument;
}

bool AFLTransform::OnBlock(const TransformPolicyInterface* policy,
                           BlockGraph* block_graph,
                           BlockGraph::Block* block) {
  total_blocks_++;

  if (block->type() != BlockGraph::CODE_BLOCK)
    return true;

  // We exclude gap blocks early to not bias the percentage of instrumentation.
  // Some binaries have a lot of them and give the impression of a poor
  // instrumentation ratio when it is actually not the case.
  // It also avoids to have stdout flooded when using the verbose mode and
  // not forcing decomposition (as the PE policy rejects gap blocks).
  if (block->attributes() & BlockGraph::GAP_BLOCK)
    return true;

  total_code_blocks_++;

  // Use the policy to skip blocks that aren't eligible for basic block
  // decomposition. Let the user be able to override it though.
  if (!force_decompose_) {
    if (!policy->BlockIsSafeToBasicBlockDecompose(block)) {
      VLOG(1) << "Not instrumenting " << block->name();
      return true;
    }
  }

  if (!ShouldInstrumentBlock(block)) {
    return true;
  }

  if (!ApplyBasicBlockSubGraphTransform(this, policy, block_graph, block,
                                        nullptr)) {
    LOG(WARNING) << "ApplyBasicBlockSubGraphTransform failed, but ignoring.";
    return true;
  }

  total_code_blocks_instrumented_++;
  return true;
}

bool AFLTransform::PostBlockGraphIteration(
    const TransformPolicyInterface* policy,
    BlockGraph* block_graph,
    BlockGraph::Block* header_block) {
  uint32_t instrumentation_percentage =
      (total_code_blocks_instrumented_ * 100) / total_code_blocks_;
  VLOG(1) << "            Blocks found: " << total_blocks_;
  VLOG(1) << "       Code Blocks found: " << total_code_blocks_;
  LOG(INFO) << "Code Blocks instrumented: " << total_code_blocks_instrumented_
            << " (" << instrumentation_percentage << "%)";
  return true;
}

void AFLTransform::instrument(BasicBlockAssembler& assm, size_t rand_id) {
  BasicBlockAssembler::Operand afl_prev_loc(
      Displacement(afl_static_cov_data_, kOffsetPrevLoc)),
      afl_area_ptr(Displacement(afl_static_cov_data_, kOffsetAreaPtr)),
      tls_index(Displacement(afl_static_cov_data_, kOffsetTlsIndex));

  // Save initial state.
  assm.push(assm::eax);
  assm.push(assm::ebx);

  if (multithread_)
    assm.push(assm::ecx);

  assm.lahf();
  assm.set(assm::kOverflow, assm::eax);

  if (multithread_) {
    // mov ecx, tls_index
    assm.mov(assm::ecx, tls_index);
    // mov ebx, fs:[2C]
    assm.mov_fs(assm::ebx, Immediate(kOffsetTebStorage));
    // mov ecx, [ebx + ecx * 4]
    assm.mov(assm::ecx, Operand(assm::ebx, assm::ecx, assm::kTimes4));
    // lea ecx, [ecx + offset]
    assm.lea(assm::ecx,
             Operand(assm::ecx, Displacement(tls_afl_prev_loc_displacement_)));
  }

  // mov ebx, ID
  assm.mov(assm::ebx, Immediate(rand_id, assm::kSize32Bit));

  if (multithread_) {
    // xor ebx, [ecx]
    assm.xor(assm::ebx, Operand(assm::ecx));
  } else {
    // xor ebx, [afl_prev_loc]
    assm.xor(assm::ebx, afl_prev_loc);
  }

  // add ebx, [afl_area_ptr]
  assm.add(assm::ebx, afl_area_ptr);
  // inc byte [ebx]
  assm.inc(Operand(assm::ebx));

  if (multithread_) {
    // mov [ecx], id >> 1
    assm.mov(Operand(assm::ecx), Immediate(rand_id >> 1, assm::kSize32Bit));
  } else {
    // mov [afl_prev_loc], id >> 1
    assm.mov(afl_prev_loc, Immediate(rand_id >> 1, assm::kSize32Bit));
  }

  // Restore initial state.
  assm.add(assm::al, Immediate(0x7F, assm::kSize8Bit));
  assm.sahf();

  if (multithread_)
    assm.pop(assm::ecx);

  assm.pop(assm::ebx);
  assm.pop(assm::eax);
}

// This is the PRNG used to assign random IDs to basic-blocks.
static RandomCtr random_ctr(kMapSize);

bool AFLTransform::TransformBasicBlockSubGraph(
    const TransformPolicyInterface* policy,
    BlockGraph* block_graph,
    BasicBlockSubGraph* basic_block_subgraph) {
  // Iterate through every basic-block and instrument them.
  BasicBlockSubGraph::BBCollection& basic_blocks =
      basic_block_subgraph->basic_blocks();

  for (auto& bb : basic_blocks) {
    BasicCodeBlock* bc_block = BasicCodeBlock::Cast(bb);
    if (bc_block == nullptr) {
      continue;
    }

    BasicBlock::Instructions& instructions = bc_block->instructions();
    BasicBlockAssembler assm(instructions.begin(), &instructions);

    size_t rand_id = random_ctr.next();
    instrument(assm, rand_id);

    BlockGraph::Block::SourceRange source_range;
    if (!GetBasicBlockSourceRange(*bc_block, &source_range)) {
      LOG(WARNING) << "Unable to get source range for basic block '"
                   << bc_block->name() << "'";
    } else {
      bb_ranges_.push_back(source_range);
    }
  }

  return true;
}

}  // namespace transforms
}  // namespace instrument

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

#include "syzygy/instrument/transforms/security_cookie_check_hook_transform.h"

#include "syzygy/pe/pe_utils.h"

namespace instrument {
namespace transforms {

using block_graph::Displacement;
using block_graph::Operand;

const char SecurityCookieCheckHookTransform::kTransformName[] =
    "SecurityCookieCheckHookTransform";

const char SecurityCookieCheckHookTransform::kReportGsFailure[] =
    "__report_gsfailure";

const char SecurityCookieCheckHookTransform::kSyzygyReportGsFailure[] =
    "__syzygy_report_gsfailure";

const uint32_t SecurityCookieCheckHookTransform::kInvalidUserAddress =
    0xdeadbeef;

bool SecurityCookieCheckHookTransform::TransformBlockGraph(
    const TransformPolicyInterface* policy,
    BlockGraph* block_graph,
    BlockGraph::Block* header_block) {
  BlockGraph::Block* report_gsfailure = nullptr;
  BlockGraph::BlockMap& blocks = block_graph->blocks_mutable();
  for (auto& block : blocks) {
    std::string name(block.second.name());
    if (name == kReportGsFailure) {
      report_gsfailure = &block.second;
      break;
    }
  }

  if (report_gsfailure == nullptr) {
    LOG(ERROR) << "Could not find " << kReportGsFailure << ".";
    return false;
  }

  if (report_gsfailure->referrers().size() != 1) {
    // We bail out if we don't have a single referrer as the only
    // expected referrer is supposed to be __security_cookie_check.
    // If there is more than one, we would rather bail out than take
    // a chance at modifying the behavior of the PE image.
    LOG(ERROR) << "Only a single referrer to " << kReportGsFailure
               << " is expected.";
    return false;
  }

  LOG(INFO) << "Found a " << kReportGsFailure
            << " implementation, hooking it now.";
  BlockGraph::Section* section_text = block_graph->FindOrAddSection(
      pe::kCodeSectionName, pe::kCodeCharacteristics);

  // All of the below is needed to build the instrumentation via the assembler.
  BasicBlockSubGraph bbsg;
  BasicBlockSubGraph::BlockDescription* block_desc = bbsg.AddBlockDescription(
      kSyzygyReportGsFailure, nullptr, BlockGraph::CODE_BLOCK,
      section_text->id(), 1, 0);

  BasicCodeBlock* bb = bbsg.AddBasicCodeBlock(kSyzygyReportGsFailure);
  block_desc->basic_block_order.push_back(bb);
  BasicBlockAssembler assm(bb->instructions().begin(), &bb->instructions());
  assm.mov(Operand(Displacement(kInvalidUserAddress)), assm::eax);

  // Condense into a block.
  BlockBuilder block_builder(block_graph);
  if (!block_builder.Merge(&bbsg)) {
    LOG(ERROR) << "Failed to build " << kSyzygyReportGsFailure << " block.";
    return false;
  }

  DCHECK_EQ(1u, block_builder.new_blocks().size());

  // Transfer the referrers to the new block, and delete the old one.
  BlockGraph::Block* syzygy_report_gsfailure =
      block_builder.new_blocks().front();
  report_gsfailure->TransferReferrers(
      0, syzygy_report_gsfailure,
      BlockGraph::Block::kTransferInternalReferences);

  report_gsfailure->RemoveAllReferences();
  if (!block_graph->RemoveBlock(report_gsfailure)) {
    LOG(ERROR) << "Removing " << kReportGsFailure << " failed.";
    return false;
  }

  return true;
}

}  // namespace transforms
}  // namespace instrument

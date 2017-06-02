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

#include "syzygy/instrument/transforms/add_implicit_tls_transform.h"

#include <windows.h>

#include "syzygy/block_graph/typed_block.h"
#include "syzygy/pe/pe_utils.h"

namespace instrument {
namespace transforms {

using block_graph::TypedBlock;

const char AddImplicitTlsTransform::kTransformName[] =
    "AddImplicitTlsTransform";

const char AddImplicitTlsTransform::kTlsIndex[] = "_tls_index";

const char AddImplicitTlsTransform::kTlsUsed[] = "_tls_used";

const char AddImplicitTlsTransform::kTlsSectionName[] = ".syzytls";

#pragma pack(push, 1)

// Describe the layout of the '.syzytls' section when we create it from scratch.
struct TlsSectionContent {
  uint32_t tls_start;
  uint32_t tls_slot;
  uint32_t tls_end;
};

#pragma pack(pop)

bool AddImplicitTlsTransform::TransformBlockGraph(
    const TransformPolicyInterface* policy,
    BlockGraph* block_graph,
    BlockGraph::Block* header_block) {
  bool slots_defined = false;
  const BlockGraph::BlockMap& blocks = block_graph->blocks();

  // One way to check if the image has implicit slots already defined
  // is by checking if '_tls_index' exists.
  for (auto& block : blocks) {
    std::string name(block.second.name());
    if (name == kTlsIndex) {
      slots_defined = true;
      break;
    }
  }

  if (slots_defined) {
    // In this case, we just need to insert ours.
    return InsertImplicitTlsSlot(block_graph);
  }

  // In this case, we need to inject the meta-data in the PE ourselves.
  return CreateImplicitTlsSlot(block_graph, header_block);
}

bool AddImplicitTlsTransform::CreateImplicitTlsSlot(
    BlockGraph* block_graph,
    BlockGraph::Block* header_block) {
  LOG(INFO) << "The binary doesn't have any implicit TLS slot defined, "
               "injecting one.";

  // This is the section where we place the TLS slot. We choose to create
  // a new section as opposed to using '.tls' (assuming it exists) to start
  // fresh.
  BlockGraph::Section* section_tls = block_graph->FindOrAddSection(
      kTlsSectionName, pe::kReadWriteDataCharacteristics);

  BlockGraph::Block* tls_content = block_graph->AddBlock(
      BlockGraph::DATA_BLOCK, sizeof(TlsSectionContent), "__tls_content");

  tls_content->set_section(section_tls->id());

  BlockGraph::Block* xl_z = block_graph->AddBlock(BlockGraph::DATA_BLOCK,
                                                  sizeof(uint32_t), "___xl_z");

  BlockGraph::Block* tls_used = block_graph->AddBlock(
      BlockGraph::DATA_BLOCK, sizeof(IMAGE_TLS_DIRECTORY), kTlsUsed);

  tls_used->SetReference(
      offsetof(IMAGE_TLS_DIRECTORY, StartAddressOfRawData),
      BlockGraph::Reference(BlockGraph::ABSOLUTE_REF,
                            BlockGraph::Reference::kMaximumSize, tls_content,
                            offsetof(TlsSectionContent, tls_start), 0));

  tls_used->SetReference(
      offsetof(IMAGE_TLS_DIRECTORY, EndAddressOfRawData),
      BlockGraph::Reference(BlockGraph::ABSOLUTE_REF,
                            BlockGraph::Reference::kMaximumSize, tls_content,
                            offsetof(TlsSectionContent, tls_end), 0));

  tls_used->SetReference(
      offsetof(IMAGE_TLS_DIRECTORY, AddressOfIndex),
      BlockGraph::Reference(BlockGraph::ABSOLUTE_REF,
                            BlockGraph::Reference::kMaximumSize,
                            tls_index_data_block_, tls_index_offset_, 0));

  tls_used->SetReference(
      offsetof(IMAGE_TLS_DIRECTORY, AddressOfCallBacks),
      BlockGraph::Reference(BlockGraph::ABSOLUTE_REF,
                            BlockGraph::Reference::kMaximumSize, xl_z, 0, 0));

  PIMAGE_TLS_DIRECTORY tls_dir =
      PIMAGE_TLS_DIRECTORY(tls_used->AllocateData(tls_used->size()));

  tls_dir->SizeOfZeroFill = 0;
  tls_dir->Characteristics = IMAGE_SCN_ALIGN_4BYTES;

  // In the '.rdata' section we inject the IMAGE_TLS_DIRECTORY metadata
  // information. This is the glue that links everything together.
  BlockGraph::Section* section_rdata = block_graph->FindOrAddSection(
      pe::kReadOnlyDataSectionName, pe::kReadOnlyDataCharacteristics);

  tls_used->set_section(section_rdata->id());
  xl_z->set_section(section_rdata->id());

  // We control the layout of the section so we know where the slot is.
  tls_displacement_ = offsetof(TlsSectionContent, tls_slot);

  TypedBlock<IMAGE_DOS_HEADER> dos_header;
  TypedBlock<IMAGE_NT_HEADERS> nt_headers;

  if (!dos_header.Init(0, header_block) ||
      !dos_header.Dereference(dos_header->e_lfanew, &nt_headers)) {
    LOG(ERROR) << "Unable to dereference NT headers.";
    return false;
  }

  IMAGE_DATA_DIRECTORY& tls_dir_info =
      nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];

  tls_dir_info.VirtualAddress = 0;
  tls_dir_info.Size = sizeof(IMAGE_TLS_DIRECTORY);

  // Link the TLS Directory RVA to the __tls_used block.
  nt_headers.SetReference(BlockGraph::RELATIVE_REF, tls_dir_info.VirtualAddress,
                          tls_used, 0, 0);

  return true;
}

bool AddImplicitTlsTransform::InsertImplicitTlsSlot(BlockGraph* block_graph) {
  LOG(INFO) << "The binary has implicit TLS slot(s) defined, appending one.";
  const BlockGraph::BlockMap& blocks = block_graph->blocks();
  const BlockGraph::Block* tls_used = nullptr;

  for (const auto& block : blocks) {
    std::string name(block.second.name());
    if (name == kTlsUsed) {
      tls_used = &block.second;
      break;
    }
  }

  if (tls_used == nullptr) {
    LOG(ERROR) << "Could not find " << kTlsUsed << ".";
    return false;
  }

  BlockGraph::Reference tls_end_ref;
  if (!tls_used->GetReference(
          offsetof(IMAGE_TLS_DIRECTORY, EndAddressOfRawData), &tls_end_ref)) {
    LOG(ERROR) << "Could not get a reference onto __tls_end.";
    return false;
  }

  BlockGraph::Reference tls_index_ref;
  if (!tls_used->GetReference(offsetof(IMAGE_TLS_DIRECTORY, AddressOfIndex),
                              &tls_index_ref)) {
    LOG(ERROR) << "Could not get a reference onto __tls_index.";
    return false;
  }

  BlockGraph::Block* tls_block = tls_end_ref.referenced();

  // Adding 4 new bytes for our slot.
  tls_displacement_ = tls_end_ref.offset();
  tls_block->InsertData(tls_displacement_, sizeof(uint32_t), true);

  // Now we need to remove the "old" __tls_index and transfer it over
  // to the new block.
  BlockGraph::Block* old_tls_index = tls_index_ref.referenced();
  old_tls_index->TransferReferrers(
      tls_index_offset_, tls_index_data_block_,
      BlockGraph::Block::kTransferInternalReferences);

  old_tls_index->RemoveAllReferences();
  if (!block_graph->RemoveBlock(old_tls_index)) {
    LOG(ERROR) << "Removing old_tls_index failed.";
    return false;
  }

  return true;
}

}  // namespace transforms
}  // namespace instrument

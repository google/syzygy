// Copyright 2011 Google Inc.
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
#include "syzygy/pe/pe_utils.h"

namespace pe {

using core::BlockGraph;
using core::RelativeAddress;

namespace {

template <typename BlockPtr>
BlockPtr UncheckedGetNtHeadersBlockFromDosHeaderBlock(
    BlockPtr dos_header_block) {
  BlockGraph::Reference ref;
  if (!dos_header_block->GetReference(offsetof(IMAGE_DOS_HEADER, e_lfanew),
                                      &ref)) {
    // No NT headers reference.
    return NULL;
  }

  if (ref.offset() != 0 ||
      ref.type() != BlockGraph::RELATIVE_REF ||
      ref.size() != sizeof(RelativeAddress)) {
    // The reference is of incorrect type.
    return NULL;
  }

  return ref.referenced();
}

template <typename BlockPtr>
BlockPtr CheckedGetNtHeadersBlockFromDosHeaderBlock(
    BlockPtr dos_header_block) {
  DCHECK(IsValidDosHeaderBlock(dos_header_block));

  BlockPtr nt_headers_block =
      UncheckedGetNtHeadersBlockFromDosHeaderBlock(dos_header_block);
  if (nt_headers_block == NULL ||
      !IsValidNtHeadersBlock(nt_headers_block)) {
    return NULL;
  }

  return nt_headers_block;
}

}  // namespace

bool IsValidDosHeaderBlock(const BlockGraph::Block* dos_header_block) {
  if (dos_header_block->size() < sizeof(IMAGE_DOS_HEADER) ||
      dos_header_block->data_size() < sizeof(IMAGE_DOS_HEADER)) {
    // Too short or not enough data.
    return false;
  }
  DCHECK(dos_header_block->data() != NULL);

  const IMAGE_DOS_HEADER* dos_header =
      reinterpret_cast<const IMAGE_DOS_HEADER*>(dos_header_block->data());
  if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
    // Wrong signature.
    return false;
  }

  // The "DOS file size" is encoded in a rather wonky manner.
  // - e_cp is the number of "pages" in the file, but
  // - e_cblp is the number of bytes used on the last page.
  size_t dos_file_size = 512 * dos_header->e_cp;
  if (dos_header->e_cblp != 0) {
    // Let's not go below zero size.
    if (dos_file_size < 512)
      return false;

    dos_file_size -= 512;
    dos_file_size += dos_header->e_cblp;
  }
  // The VC linker yields a DOS header with a size that's larger than
  // the DOS header and the NT headers combined. I wonder if anyone cares
  // about these sizes anymore.
  if (dos_file_size < dos_header_block->size())
    return false;

  // Check the paragraph size of the header.
  if (dos_header->e_cparhdr * 16 < sizeof(IMAGE_DOS_HEADER))
    return false;

  // Retrieve the NT headers.
  const BlockGraph::Block* nt_headers =
      UncheckedGetNtHeadersBlockFromDosHeaderBlock(dos_header_block);
  if (nt_headers == NULL) {
    // No DOS header reference.
    return false;
  }

  return true;
}

bool IsValidNtHeadersBlock(const BlockGraph::Block* nt_headers_block) {
  if (nt_headers_block->size() < sizeof(IMAGE_NT_HEADERS) ||
      nt_headers_block->data_size() < sizeof(IMAGE_NT_HEADERS)) {
    // Too short or not enough data.
    return false;
  }
  DCHECK(nt_headers_block->data() != NULL);

  // Check the signatures.
  const IMAGE_NT_HEADERS* nt_headers =
      reinterpret_cast<const IMAGE_NT_HEADERS*>(nt_headers_block->data());
  if (nt_headers->Signature!= IMAGE_NT_SIGNATURE) {
    // Wrong signature.
    return false;
  }
  if (nt_headers->FileHeader.SizeOfOptionalHeader !=
      sizeof(IMAGE_OPTIONAL_HEADER)) {
    // Wrong optional header size.
    return false;
  }
  if (nt_headers->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC) {
    // Wrong magic for optional header.
    return false;
  }

  // Calculate the minimum size for the NT headers and the section header.
  size_t header_size = sizeof(IMAGE_NT_HEADERS) +
      sizeof(IMAGE_SECTION_HEADER) * nt_headers->FileHeader.NumberOfSections;

  if (nt_headers_block->size() < header_size ||
      nt_headers_block->data_size() < header_size) {
    // The block's size isn't large enough for the section headers.
    return false;
  }

  return true;
}

const BlockGraph::Block* GetNtHeadersBlockFromDosHeaderBlock(
    const BlockGraph::Block* dos_header_block) {
  return CheckedGetNtHeadersBlockFromDosHeaderBlock(dos_header_block);
}

BlockGraph::Block* GetNtHeadersBlockFromDosHeaderBlock(
    BlockGraph::Block* dos_header_block) {
  return CheckedGetNtHeadersBlockFromDosHeaderBlock(dos_header_block);
}

}  // namespace pe

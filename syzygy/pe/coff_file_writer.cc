// Copyright 2013 Google Inc. All Rights Reserved.
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

#include "syzygy/pe/coff_file_writer.h"

#include <cstdio>

#include "base/file_util.h"
#include "base/win/scoped_handle.h"
#include "syzygy/block_graph/block_graph.h"

namespace pe {

using block_graph::BlockGraph;
using core::RelativeAddress;

CoffFileWriter::CoffFileWriter(const ImageLayout* image_layout)
    : image_layout_(image_layout) {
}

bool CoffFileWriter::WriteImage(const base::FilePath& path) {
  DCHECK(image_layout_ != NULL);

  // Overwrite the destination file.
  base::ScopedFILE file(base::OpenFile(path, "wb"));
  if (file.get() == NULL) {
    LOG(ERROR) << "Unable to open file " << path.value() << ".";
    return false;
  }

  // Write every range in order. In a COFF file, block graph relative
  // addresses match file offsets, so writing out the file can simply be
  // done in address order, with appropriate padding.
  std::vector<uint8> padding;
  RelativeAddress cursor(0);
  BlockGraph::AddressSpace::RangeMapConstIter it =
      image_layout_->blocks.begin();
  for (; it != image_layout_->blocks.end(); ++it) {
    // Pad up to the address of the next block.
    DCHECK_LE(cursor, it->first.start());
    size_t pad_size = it->first.start() - cursor;
    if (pad_size > 0) {
      if (pad_size > padding.size())
        padding.resize(pad_size, 0);
      if (std::fwrite(&padding[0], sizeof(padding[0]), pad_size,
                      file.get()) != pad_size) {
        LOG(ERROR) << "Unable to write padding (" << pad_size
                   << " bytes) to file.";
        return false;
      }
      cursor += pad_size;
    }

    const BlockGraph::Block* block = it->second;

    // Ignore BSS blocks.
    if ((block->attributes() & BlockGraph::COFF_BSS) != 0)
      continue;

    // Write the contents of the block.
    DCHECK(block != NULL);
    const uint8* data = block->data();
    size_t data_size = block->data_size();
    if (std::fwrite(data, sizeof(*data), data_size, file.get()) != data_size) {
      LOG(ERROR) << "Unable to write contents of block \""
                 << block->name() << "\" ("
                 << data_size << " bytes) to file.";
      return false;
    }

    // Advance cursor.
    cursor += block->data_size();
    DCHECK_EQ(it->first.end(), cursor);
  }

  return true;
}

}  // namespace pe

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

#include "syzygy/pe/image_layout.h"

#include "base/file_util.h"
#include "base/logging.h"
#include "syzygy/pe/pe_file.h"

namespace pe {

void CopySectionHeadersToImageLayout(
    size_t num_sections,
    const IMAGE_SECTION_HEADER* section_headers,
    std::vector<ImageLayout::SectionInfo>* sections) {
  DCHECK(num_sections > 0);
  DCHECK(section_headers != NULL);
  DCHECK(sections != NULL);

  sections->clear();
  sections->reserve(num_sections);
  for (size_t i = 0; i < num_sections; ++i) {
    sections->push_back(pe::ImageLayout::SectionInfo());
    pe::ImageLayout::SectionInfo& section = sections->back();

    section.name = PEFile::GetSectionName(section_headers[i]);
    section.addr.set_value(section_headers[i].VirtualAddress);
    section.size = section_headers[i].Misc.VirtualSize;
    section.data_size = section_headers[i].SizeOfRawData;
    section.characteristics = section_headers[i].Characteristics;
  }
}

ImageLayout::ImageLayout(block_graph::BlockGraph* block_graph)
    : blocks(block_graph) {
}

}  // namespace pe

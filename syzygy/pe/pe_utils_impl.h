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
//
// Template implementation of some PE/COFF utilities.

#ifndef SYZYGY_PE_PE_UTILS_IMPL_H_
#define SYZYGY_PE_PE_UTILS_IMPL_H_

namespace pe {

template <typename ImageFile>
bool CopySectionInfoToBlockGraph(const ImageFile& image_file,
                                 block_graph::BlockGraph* block_graph) {
  // Iterate through the image sections, and create sections in the BlockGraph.
  size_t num_sections = image_file.file_header()->NumberOfSections;
  for (size_t i = 0; i < num_sections; ++i) {
    const IMAGE_SECTION_HEADER* header = image_file.section_header(i);
    std::string name = ImageFile::GetSectionName(*header);
    block_graph::BlockGraph::Section* section = block_graph->AddSection(
        name, header->Characteristics);
    DCHECK(section != NULL);

    // For now, we expect them to have been created with the same IDs as those
    // in the original image.
    if (section->id() != i) {
      LOG(ERROR) << "Unexpected section ID.";
      return false;
    }
  }

  return true;
}

}  // namespace pe

#endif  // SYZYGY_PE_PE_UTILS_IMPL_H_

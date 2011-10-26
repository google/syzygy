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

void CopyNtHeaderToImageLayout(const IMAGE_NT_HEADERS* nt_headers,
                               ImageLayout::HeaderInfo* header_info) {
  DCHECK(nt_headers != NULL);
  DCHECK(header_info != NULL);

  header_info->characteristics =
      nt_headers->FileHeader.Characteristics;
  header_info->major_linker_version =
      nt_headers->OptionalHeader.MajorLinkerVersion;
  header_info->minor_linker_version =
      nt_headers->OptionalHeader.MinorLinkerVersion;
  header_info->image_base =
      nt_headers->OptionalHeader.ImageBase;
  header_info->section_alignment =
      nt_headers->OptionalHeader.SectionAlignment;
  header_info->file_alignment =
      nt_headers->OptionalHeader.FileAlignment;
  header_info->major_operating_system_version =
      nt_headers->OptionalHeader.MajorOperatingSystemVersion;
  header_info->minor_operating_system_version =
      nt_headers->OptionalHeader.MinorOperatingSystemVersion;
  header_info->major_image_version =
      nt_headers->OptionalHeader.MajorImageVersion;
  header_info->minor_image_version =
      nt_headers->OptionalHeader.MinorImageVersion;
  header_info->major_subsystem_version =
      nt_headers->OptionalHeader.MajorSubsystemVersion;
  header_info->minor_subsystem_version =
      nt_headers->OptionalHeader.MinorSubsystemVersion;
  header_info->win32_version_value =
      nt_headers->OptionalHeader.Win32VersionValue;
  header_info->size_of_headers =
      nt_headers->OptionalHeader.SizeOfHeaders;
  header_info->subsystem =
      nt_headers->OptionalHeader.Subsystem;
  header_info->dll_characteristics =
      nt_headers->OptionalHeader.DllCharacteristics;
  header_info->size_of_stack_reserve =
      nt_headers->OptionalHeader.SizeOfStackReserve;
  header_info->size_of_stack_commit =
      nt_headers->OptionalHeader.SizeOfStackCommit;
  header_info->size_of_heap_reserve =
      nt_headers->OptionalHeader.SizeOfHeapReserve;
  header_info->size_of_heap_commit =
      nt_headers->OptionalHeader.SizeOfHeapCommit;
  header_info->loader_flags =
      nt_headers->OptionalHeader.LoaderFlags;
}

void CopySectionHeadersToImageLayout(
    size_t num_sections,
    const IMAGE_SECTION_HEADER* section_headers,
    std::vector<ImageLayout::SegmentInfo>* segments) {
  DCHECK(num_sections > 0);
  DCHECK(section_headers != NULL);
  DCHECK(segments != NULL);

  segments->clear();
  segments->reserve(num_sections);
  for (size_t i = 0; i < num_sections; ++i) {
    segments->push_back(pe::ImageLayout::SegmentInfo());
    pe::ImageLayout::SegmentInfo& segment = segments->back();

    segment.name = PEFile::GetSectionName(section_headers[i]);
    segment.addr.set_value(section_headers[i].VirtualAddress);
    segment.size = section_headers[i].Misc.VirtualSize;
    segment.data_size = section_headers[i].SizeOfRawData;
    segment.characteristics = section_headers[i].Characteristics;
  }
}

ImageLayout::ImageLayout(core::BlockGraph* block_graph)
    : blocks(block_graph) {
  memset(&header_info, 0, sizeof(header_info));
}

}  // namespace pe

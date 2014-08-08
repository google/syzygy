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

#include "syzygy/pe/serialization.h"

#include "base/bind.h"
#include "base/file_util.h"
#include "syzygy/block_graph/typed_block.h"
#include "syzygy/pe/find.h"
#include "syzygy/pe/image_layout.h"
#include "syzygy/pe/metadata.h"
#include "syzygy/pe/pe_file.h"

namespace pe {

namespace {

using block_graph::BlockGraph;
using block_graph::BlockGraphSerializer;

// Used for versioning the serialized stream. Be sure to change this if
// non-backwards compatible changes are made to the stream layout.
static const uint32 kSerializedBlockGraphAndImageLayoutVersion = 0;

bool MetadataMatchesPEFile(const Metadata& metadata, const PEFile& pe_file) {
  PEFile::Signature pe_signature;
  pe_file.GetSignature(&pe_signature);

  // We are careful to use PEFile::Signature::IsConsistent rather than
  // Metadata::IsConsistent. This is because we explicitly want to handle
  // backwards compatibility with differing versions of the toolchain. Instead,
  // we version the whole serialized stream and enforce consistency in
  // LoadBlockGraphAndImageLayout.
  if (metadata.module_signature().IsConsistent(pe_signature))
    return true;

  // If the PE signature doesn't match outright, it's perhaps because the PE
  // file has been modified after we captured it's metadata. This can happen in
  // the case where e.g. a file is signed, which updates the data directory
  // to point to the signatures.
  if (metadata.module_signature().IsConsistentExceptForChecksum(pe_signature)) {
    LOG(WARNING) << "Matching PE module with modified checksum. "
                    "Beware that this may be unsafe if the module has been "
                    "significantly modified.\n"
                    "Significant modification includes e.g. modifying "
                    "resources.\n"
                    "Signing files does, however, not constitute significant "
                    "modification, so if you're e.g. instrumenting official "
                    "Chrome binaries, you'll be fine.";

    return true;
  }

  return false;
}

bool FindPEFile(const Metadata& metadata, PEFile* pe_file) {
  DCHECK(pe_file != NULL);

  LOG(INFO) << "Searching for module to use in deserialization.";

  // We search for a PE file in the following sequence:
  // (1) If pe_file is already initialized, try to use it.
  // (2) Look for a PE file using the path stored in metadata.
  // (3) Search for a matching PE file in the already initialized pe_file
  //     directory (if provided), and the metadata directory.
  // (4) Search for a matching PE file using a system wide search.
  std::wstring search_path;

  // Approach 1: If we already have a PE file initialized, see if it matches the
  // signature of the one we serialized.
  if (!pe_file->path().empty()) {
    LOG(INFO) << "Attempting to use provided module in deserialization: "
              << pe_file->path().value();

    if (MetadataMatchesPEFile(metadata, *pe_file))
      return true;

    // Save the directory of the provided PE file in the search path.
    search_path.append(pe_file->path().DirName().value());
    search_path.append(L";");
    LOG(WARNING) << "Metadata signature does not match provided module: "
                 << pe_file->path().value();
  }

  // Approach 2: Try to use the path provided in the metadata itself.
  base::FilePath metadata_path(metadata.module_signature().path);
  LOG(INFO) << "Attempting to use metadata path in deserialization: "
            << metadata_path.value();
  if (!base::PathExists(metadata_path) || !pe_file->Init(metadata_path)) {
    LOG(WARNING) << "Unable to read module:" << metadata_path.value();
  } else {
    if (MetadataMatchesPEFile(metadata, *pe_file))
      return true;

    // Append the directory to the search path if it exists.
    base::FilePath dir = metadata_path.DirName();
    if (base::DirectoryExists(dir))
      search_path.append(metadata_path.DirName().value());

    LOG(WARNING) << "Metadata signature does not match metadata module: "
                 << metadata_path.value();
  }

  base::FilePath module_path;

  // Approach 3: Use an explicit search in the provided paths.
  if (!search_path.empty()) {
    LOG(INFO) << "Searching for module in provided paths: " << search_path;
    if (!FindModuleBySignature(metadata.module_signature(),
                               search_path.c_str(),
                               &module_path)) {
      LOG(WARNING) << "FindModuleBySignature failed.";
    }
  }

  // Approach 4: Do a system-wide search.
  if (module_path.empty()) {
    LOG(INFO) << "Searching for module using system paths.";
    if (!FindModuleBySignature(metadata.module_signature(),
                               &module_path)) {
      LOG(ERROR) << "FindModuleBySignature failed.";
      return false;
    }
  }

  // No module found in either of the above two searches?
  if (module_path.empty()) {
    LOG(ERROR) << "No module found in FindModuleBySignature.";
    return false;
  }

  // If we get here, we've found a module. However, we don't just accept that
  // fact.

  if (!pe_file->Init(module_path)) {
    LOG(ERROR) << "Failed to read module: " << module_path.value();
    return false;
  }

  if (!MetadataMatchesPEFile(metadata, *pe_file)) {
    LOG(ERROR) << "Metadata signature does not match found module: "
               << module_path.value();
    return false;
  }

  LOG(INFO) << "Found module with matching signature: " << module_path.value();

  return true;
}

// This callback is used to save the data in a block by simply savings its
// address in the image-layout.
bool SaveBlockData(const ImageLayout* image_layout,
                   bool data_already_saved,
                   const BlockGraph::Block& block,
                   core::OutArchive* out_archive) {
  DCHECK(image_layout != NULL);
  DCHECK(out_archive != NULL);

  // We're always in OUTPUT_NO_DATA mode, so either the data hasn't yet been
  // saved or there was no data to save.
  DCHECK(block.data_size() == 0 || !data_already_saved);

  core::RelativeAddress block_addr;
  if (!image_layout->blocks.GetAddressOf(&block, &block_addr)) {
    LOG(ERROR) << "Block with id " << block.id() << " not in image-layout.";
    return false;
  }

  // Save the address of the block wrt to the provided image-layout. This will
  // be sufficient for us to lookup the block data in the PE file afterwards.
  if (!out_archive->Save(block_addr)) {
    LOG(ERROR) << "Unable to save address of block with id " << block.id()
               << ".";
    return false;
  }

  return true;
}

// This callback is used to load the data in a block. It also simultaneously
// constructs the image-layout.
bool LoadBlockData(const PEFile* pe_file,
                   ImageLayout* image_layout,
                   bool need_to_set_data,
                   size_t data_size,
                   BlockGraph::Block* block,
                   core::InArchive* in_archive) {
  DCHECK(pe_file != NULL);
  DCHECK(image_layout != NULL);
  DCHECK(block != NULL);
  DCHECK(in_archive != NULL);

  core::RelativeAddress block_addr;
  if (!in_archive->Load(&block_addr)) {
    LOG(ERROR) << "Unable to load address in image-layout of block with id "
               << block->id() << ".";
    return false;
  }

  // Insert the block in the image layout.
  if (!image_layout->blocks.InsertBlock(block_addr, block)) {
    LOG(ERROR) << "Unable to insert block with id " << block->id() << " into "
               << "image-layout.";
    return false;
  }

  // If we have no data in this block then there's no need to load any.
  if (data_size == 0)
    return true;

  // We're in OUTPUT_NO_DATA mode, so we should always be responsible for
  // setting the block data.
  DCHECK(need_to_set_data);
  DCHECK_EQ(0u, block->data_size());
  DCHECK(block->data() == NULL);

  const uint8* data = pe_file->GetImageData(block_addr, data_size);
  if (data == NULL) {
    LOG(ERROR) << "Unable to get data from PE file for block with id "
               << block->id() << ".";
    return false;
  }

  block->SetData(data, data_size);

  return true;
}

bool LoadBlockGraphAndImageLayout(
    const PEFile& pe_file,
    PEFile* pe_file_ptr,
    block_graph::BlockGraphSerializer::Attributes* attributes,
    ImageLayout* image_layout,
    core::InArchive* in_archive) {
  DCHECK(pe_file_ptr == NULL || pe_file_ptr == &pe_file);
  DCHECK(image_layout != NULL);
  DCHECK(in_archive != NULL);

  BlockGraph* block_graph = image_layout->blocks.graph();

  // Load and check the stream version. This is where we could dispatch to
  // different handlers for old versions of the stream if we wish to maintain
  // backwards compatibility.
  uint32 stream_version = 0;
  if (!in_archive->Load(&stream_version)) {
    LOG(ERROR) << "Unable to load serialized stream version.";
    return false;
  }
  if (stream_version != kSerializedBlockGraphAndImageLayoutVersion) {
    LOG(ERROR) << "Invalid stream version " << stream_version << ", expected "
               << kSerializedBlockGraphAndImageLayoutVersion << ".";
    return false;
  }

  // Load the metadata.
  Metadata metadata;
  if (!in_archive->Load(&metadata)) {
    LOG(ERROR) << "Unable to load metadata.";
    return false;
  }

  if (pe_file_ptr != NULL) {
    // If we've been given a modifiable PE-file, then we can be more intelligent
    // about our search. This call logs verbosely on failure so we don't have
    // to.
    if (!FindPEFile(metadata, pe_file_ptr))
      return false;
  } else {
    if (!MetadataMatchesPEFile(metadata, pe_file)) {
      LOG(ERROR) << "Provided PE file does not match signature in serialized "
                 << "stream.";
      return false;
    }
  }

  // Set up the serializer.
  BlockGraphSerializer bgs;
  bgs.set_load_block_data_callback(
      base::Bind(&LoadBlockData,
                 base::Unretained(&pe_file),
                 base::Unretained(image_layout)));

  // Now deserialize the block-graph. This will simultaneously deserialize the
  // image-layout address-space.
  if (!bgs.Load(block_graph, in_archive)) {
    LOG(ERROR) << "Unable to load block-graph.";
    return false;
  }

  // Return the attributes if asked to.
  if (attributes != NULL)
    *attributes = bgs.attributes();

  // We can now recreate the rest of the image-layout from the block-graph.
  // Start by retrieving the DOS header block, which is always at the start of
  // the image.
  BlockGraph::Block* dos_header_block =
      image_layout->blocks.GetBlockByAddress(core::RelativeAddress());
  if (dos_header_block == NULL) {
    LOG(ERROR) << "Unable to find DOS header in image-layout address-space.";
    return false;
  }

  // Cast this as an IMAGE_DOS_HEADER.
  block_graph::ConstTypedBlock<IMAGE_DOS_HEADER> dos_header;
  if (!dos_header.Init(0, dos_header_block)) {
    LOG(ERROR) << "Unable to cast DOS header block to IMAGE_DOS_HEADER.";
    return false;
  }

  // Get the NT headers.
  block_graph::ConstTypedBlock<IMAGE_NT_HEADERS> nt_headers;
  if (!dos_header.Dereference(dos_header->e_lfanew, &nt_headers)) {
    LOG(ERROR) << "Unable to dereference NT headers from DOS header.";
    return false;
  }

  // Finally, use these headers to populate the section info vector of the
  // image-layout.
  if (!CopyHeaderToImageLayout(nt_headers.block(), image_layout)) {
    LOG(ERROR) << "Unable to copy NT headers to image-layout.";
    return false;
  }

  return true;
}

}  // namespace

bool SaveBlockGraphAndImageLayout(
    const PEFile& pe_file,
    block_graph::BlockGraphSerializer::Attributes attributes,
    const ImageLayout& image_layout,
    core::OutArchive* out_archive) {
  DCHECK(out_archive != NULL);

  const BlockGraph& block_graph = *image_layout.blocks.graph();

  if (!out_archive->Save(kSerializedBlockGraphAndImageLayoutVersion)) {
    LOG(ERROR) << "Unable to save serialized stream version.";
    return false;
  }

  // Get the metadata for this module and the toolchain. This will
  // allow us to validate input files in other pieces of the toolchain.
  Metadata metadata;
  PEFile::Signature pe_file_signature;
  pe_file.GetSignature(&pe_file_signature);
  if (!metadata.Init(pe_file_signature)) {
    LOG(ERROR) << "Unable to initialize metadata for PE file \""
               << pe_file.path().value() << "\".";
    return false;
  }

  // Save the metadata.
  if (!out_archive->Save(metadata)) {
    LOG(ERROR) << "Unable to save metadata for PE file \""
               << pe_file.path().value() << "\".";
    return false;
  }

  // Initialize the serializer. We don't save any of the data because it can all
  // be retrieved from the PE file.
  BlockGraphSerializer bgs;
  bgs.set_data_mode(BlockGraphSerializer::OUTPUT_NO_DATA);
  bgs.set_attributes(attributes);
  bgs.set_save_block_data_callback(base::Bind(
      &SaveBlockData,
      base::Unretained(&image_layout)));

  // Write the block-graph. This also simultaneously serializes the
  // address-space portion of the image-layout.
  if (!bgs.Save(block_graph, out_archive)) {
    LOG(ERROR) << "Unable to save block-graph.";
    return false;
  }

  return true;
}

bool LoadBlockGraphAndImageLayout(
    const PEFile& pe_file,
    block_graph::BlockGraphSerializer::Attributes* attributes,
    ImageLayout* image_layout,
    core::InArchive* in_archive) {
  if (!LoadBlockGraphAndImageLayout(pe_file, NULL, attributes,
                                    image_layout, in_archive)) {
    return false;
  }

  return true;
}

bool LoadBlockGraphAndImageLayout(
    PEFile* pe_file,
    block_graph::BlockGraphSerializer::Attributes* attributes,
    ImageLayout* image_layout,
    core::InArchive* in_archive) {
  DCHECK(pe_file != NULL);
  DCHECK(image_layout != NULL);
  DCHECK(in_archive != NULL);

  if (!LoadBlockGraphAndImageLayout(*pe_file, pe_file, attributes,
                                    image_layout, in_archive)) {
    return false;
  }

  return true;
}

}  // namespace pe

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

#include "syzygy/pe/new_decomposer.h"

#include "syzygy/core/zstream.h"
#include "syzygy/pdb/pdb_byte_stream.h"
#include "syzygy/pdb/pdb_file.h"
#include "syzygy/pdb/pdb_reader.h"
#include "syzygy/pdb/pdb_util.h"
#include "syzygy/pe/dia_util.h"
#include "syzygy/pe/find.h"
#include "syzygy/pe/pe_utils.h"
#include "syzygy/pe/serialization.h"

namespace pe {

NewDecomposer::NewDecomposer(const PEFile& image_file)
    : image_file_(image_file), image_layout_(NULL), image_(NULL) {
}

bool NewDecomposer::Decompose(ImageLayout* image_layout) {
  DCHECK(image_layout != NULL);

  // The temporaries should be NULL.
  DCHECK(image_layout_ == NULL);
  DCHECK(image_ == NULL);

  // We start by finding the PDB path.
  if (!FindAndValidatePdbPath())
    return false;
  DCHECK(!pdb_path_.empty());

  // Load the serialized block-graph from the PDB if it exists. This allows
  // round-trip decomposition.
  bool stream_exists = false;
  if (LoadBlockGraphFromPdb(
          pdb_path_, image_file_, image_layout, &stream_exists)) {
    return true;
  } else if (stream_exists) {
    // If the stream exists but hasn't been loaded we return an error. At this
    // point an error message has already been logged if there was one.
    return false;
  }

  // At this point a full decomposition needs to be performed.
  image_layout_ = image_layout;
  image_ = &(image_layout->blocks);
  bool success = DecomposeImpl();
  image_layout_ = NULL;
  image_ = NULL;

  return success;
}

bool NewDecomposer::FindAndValidatePdbPath() {
  // Manually find the PDB path if it is not specified.
  if (pdb_path_.empty()) {
    if (!FindPdbForModule(image_file_.path(), &pdb_path_) ||
        pdb_path_.empty()) {
      LOG(ERROR) << "Unable to find PDB file for module: "
                 << image_file_.path().value();
      return false;
    }
  }
  DCHECK(!pdb_path_.empty());

  if (!file_util::PathExists(pdb_path_)) {
    LOG(ERROR) << "Path not found: " << pdb_path_.value();
    return false;
  }

  if (!pe::PeAndPdbAreMatched(image_file_.path(), pdb_path_)) {
    LOG(ERROR) << "PDB file \"" << pdb_path_.value() << "\" does not match "
               << "module \"" << image_file_.path().value() << "\".";
    return false;
  }

  return true;
}

bool NewDecomposer::LoadBlockGraphFromPdbStream(
    const PEFile& image_file,
    pdb::PdbStream* block_graph_stream,
    ImageLayout* image_layout) {
  DCHECK(block_graph_stream != NULL);
  DCHECK(image_layout != NULL);
  LOG(INFO) << "Reading block-graph and image layout from the PDB.";

  // Initialize an input archive pointing to the stream.
  scoped_refptr<pdb::PdbByteStream> byte_stream = new pdb::PdbByteStream();
  if (!byte_stream->Init(block_graph_stream))
    return false;
  DCHECK(byte_stream.get() != NULL);

  core::ScopedInStreamPtr pdb_in_stream;
  pdb_in_stream.reset(core::CreateByteInStream(
      byte_stream->data(), byte_stream->data() + byte_stream->length()));

  // Read the header.
  uint32 stream_version = 0;
  unsigned char compressed = 0;
  if (!pdb_in_stream->Read(sizeof(stream_version),
                           reinterpret_cast<core::Byte*>(&stream_version)) ||
      !pdb_in_stream->Read(sizeof(compressed),
                           reinterpret_cast<core::Byte*>(&compressed))) {
    LOG(ERROR) << "Failed to read existing Syzygy block-graph stream header.";
    return false;
  }

  // Check the stream version.
  if (stream_version != pdb::kSyzygyBlockGraphStreamVersion) {
    LOG(ERROR) << "PDB contains an unsupported Syzygy block-graph stream"
               << " version (got " << stream_version << ", expected "
               << pdb::kSyzygyBlockGraphStreamVersion << ").";
    return false;
  }

  // If the stream is compressed insert the decompression filter.
  core::InStream* in_stream = pdb_in_stream.get();
  scoped_ptr<core::ZInStream> zip_in_stream;
  if (compressed != 0) {
    zip_in_stream.reset(new core::ZInStream(in_stream));
    if (!zip_in_stream->Init()) {
      LOG(ERROR) << "Unable to initialize ZInStream.";
      return false;
    }
    in_stream = zip_in_stream.get();
  }

  // Deserialize the image-layout.
  core::NativeBinaryInArchive in_archive(in_stream);
  block_graph::BlockGraphSerializer::Attributes attributes = 0;
  if (!LoadBlockGraphAndImageLayout(
      image_file, &attributes, image_layout, &in_archive)) {
    LOG(ERROR) << "Failed to deserialize block-graph and image layout.";
    return false;
  }

  return true;
}

bool NewDecomposer::LoadBlockGraphFromPdb(const FilePath& pdb_path,
                                          const PEFile& image_file,
                                          ImageLayout* image_layout,
                                          bool* stream_exists) {
  DCHECK(image_layout != NULL);
  DCHECK(stream_exists != NULL);

  pdb::PdbFile pdb_file;
  pdb::PdbReader pdb_reader;
  if (!pdb_reader.Read(pdb_path, &pdb_file)) {
    LOG(ERROR) << "Unable to read the PDB named \"" << pdb_path.value()
               << "\".";
    return NULL;
  }

  // Try to get the block-graph stream from the PDB.
  scoped_refptr<pdb::PdbStream> block_graph_stream;
  if (!pdb::LoadNamedStreamFromPdbFile(pdb::kSyzygyBlockGraphStreamName,
                                       &pdb_file,
                                       &block_graph_stream) ||
      block_graph_stream.get() == NULL) {
    *stream_exists = false;
    return false;
  }
  if (block_graph_stream->length() == 0) {
    *stream_exists = false;
    LOG(WARNING) << "The block-graph stream is empty, ignoring it.";
    return false;
  }

  // The PDB contains a block-graph stream, the block-graph and the image layout
  // will be read from this stream.
  *stream_exists = true;
  if (!LoadBlockGraphFromPdbStream(image_file, block_graph_stream.get(),
                                   image_layout)) {
    return false;
  }

  return true;
}

bool NewDecomposer::DecomposeImpl() {
  return true;
}

}  // namespace pe

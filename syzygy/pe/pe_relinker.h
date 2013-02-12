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
//
// Declares PERelinker. Relinking can be seen as decomposing an input image,
// applying a sequence of block-graph transforms (some applied implicitly, and
// others provided by the user), followed by a sequence of orderers (again, some
// implicit, some provided by the user), laying-out, finalizing and finally
// writing a new image. After writing the image a similar transformation
// workflow is applied to the corresponding PDB file, consisting of applying
// any user defined PDB mutations, followed by 2-3 (depending on PeRelinker
// configuration) internal mutations (updating the GUID/age, adding the history
// stream and adding the serialized block-graph stream). PERelinker encapsulates
// this workflow.
//
// It is intended to be used as follows:
//
//   PERelinker relinker;
//   relinker.set_input_path(...);  // Required.
//   relinker.set_output_path(...);  // Required.
//   relinker.set_input_pdb_path(...);  // Optional.
//   relinker.set_output_pdb_path(...);  // Optional.
//   relinker.Init();  // Check the return value!
//
//   // At this point, the following accessors are valid:
//   relinker.input_pe_file();
//   relinker.input_image_layout();
//   relinker.block_graph();
//   relinker.dos_header_block();
//   relinker.output_guid();
//
//   relinker.AppendTransform(...);  // May be called repeatedly.
//   relinker.AppendOrderer(...);  // May be called repeatedly.
//   relinker.AppendPdbMutator(...);  // May be called repeatedly.
//
//   relinker.Relink();  // Check the return value!
//
// NOTE: This split workflow is only necessary as a workaround to deal with
//     transforms and orderers built around legacy code. Intermediate
//     representations of serialized data-structures should be stored in such
//     a way so as not to explicitly require access to the untransformed image.
//     Additionally, for checking validity a transform or orderer should require
//     no more than the PESignature associated with the original module, and/or
//     the toolchain metadata present in the module, if there was any.
//
// TODO(chrisha): Resimplify this API once Reorderer has been reworked to move
//     away from Block pointers.

#ifndef SYZYGY_PE_PE_RELINKER_H_
#define SYZYGY_PE_PE_RELINKER_H_

#include <vector>

#include "base/file_path.h"
#include "syzygy/block_graph/orderer.h"
#include "syzygy/block_graph/transform.h"
#include "syzygy/pdb/pdb_mutator.h"
#include "syzygy/pe/image_layout_builder.h"
#include "syzygy/pe/pe_file.h"

namespace pe {

// Embodies a transformation on a PE image, from decomposing an original image
// to applying some transform(s) to it, to generating the layout and finally
// writing the image and accompanying PDB to disk.
//
// Creating a PERelinker and not changing its default configuration yields an
// identity relinker that will produce an identical (nearly, except for cosmetic
// differences in some headers) image to the input.
//
// The workflow is as follows:
//
// 1. Relinker created with an input image. The PDB file is found automatically
//    and the image is decomposed. Optionally the PDB may be directly specified.
// 2. The image is transformed:
//    a) Transforms provided by the user are applied.
//    b) AddMetadataTransform is conditionally applied.
//    c) AddPdbInfoTransform is applied.
//    d) PrepareHeadersTransform is applied.
// 3. The image is ordered:
//    a) Orderers provided by the user are applied.
//    b) PEOrderer is applied.
// 4. ImageLayoutBuilder is used to convert the OrderedBlockGraph to an
//    ImageLayout.
// 5. Image and accompanying PDB file are written. (Filenames are inferred from
//    input filenames or directly specified.)
class PERelinker {
 public:
  typedef block_graph::BlockGraph BlockGraph;
  typedef block_graph::BlockGraphOrdererInterface Orderer;
  typedef block_graph::BlockGraphTransformInterface Transform;

  PERelinker();

  // @name Accessors.
  // @{
  const FilePath& input_path() const { return input_path_; }
  const FilePath& input_pdb_path() const { return input_pdb_path_; }
  const FilePath& output_path() const { return output_path_; }
  const FilePath& output_pdb_path() const { return output_pdb_path_; }
  bool add_metadata() const { return add_metadata_; }
  bool allow_overwrite() const { return allow_overwrite_; }
  bool augment_pdb() const { return augment_pdb_; }
  bool compress_pdb() const { return compress_pdb_; }
  bool parse_debug_info() const { return parse_debug_info_; }
  bool strip_strings() const { return strip_strings_; }
  bool use_new_decomposer() const { return use_new_decomposer_; }
  size_t padding() const { return padding_; }
  // @}

  // @name Mutators for controlling relinker behaviour.
  // @{
  void set_input_path(const FilePath& input_path) {
    input_path_ = input_path;
  }
  void set_input_pdb_path(const FilePath& input_pdb_path) {
    input_pdb_path_ = input_pdb_path;
  }
  void set_output_path(const FilePath& output_path) {
    output_path_ = output_path;
  }
  void set_output_pdb_path(const FilePath& output_pdb_path) {
    output_pdb_path_ = output_pdb_path;
  }
  void set_add_metadata(bool add_metadata) {
    add_metadata_ = add_metadata;
  }
  void set_allow_overwrite(bool allow_overwrite) {
    allow_overwrite_ = allow_overwrite;
  }
  void set_augment_pdb(bool augment_pdb) {
    augment_pdb_ = augment_pdb;
  }
  void set_compress_pdb(bool compress_pdb) {
    compress_pdb_ = compress_pdb;
  }
  void set_parse_debug_info(bool parse_debug_info) {
    parse_debug_info_ = parse_debug_info;
  }
  void set_strip_strings(bool strip_strings) {
    strip_strings_ = strip_strings;
  }
  void set_use_new_decomposer(bool use_new_decomposer) {
    use_new_decomposer_ = use_new_decomposer;
  }
  void set_padding(size_t padding) {
    padding_ = padding;
  }
  // @}

  // Appends a transform to be applied by this relinker. If no transforms are
  // specified, none will be applied and the transform is effectively the
  // identity transform. Each transform will be applied in the order added
  // to the relinker, assuming all earlier transforms have succeeded.
  //
  // @param transform the transform to append to the list of transforms to
  //     apply. The pointer must remain valid for the lifespan of the relinker.
  void AppendTransform(Transform* transform);

  // Appends a list of transforms to be applied by this relinker. Each transform
  // will be applied in the order added to the relinker, assuming all earlier
  // transforms have succeeded.
  //
  // @param transforms a vector of transforms to be applied to the input image.
  //     The pointers must remain valid for the lifespan of the relinker.
  void AppendTransforms(const std::vector<Transform*>& transforms);

  // Appends an orderer to be applied by this relinker.
  //
  // If no orderers are specified the default orderer will be applied. If no
  // transforms have been applied this makes the entire relinker an identity
  // relinker. Each orderer will be applied in the order added to the relinker,
  // assuming all earlier orderers have succeeded.
  //
  // @param orderer a orderer to be applied to the input image. The pointer must
  //     remain valid for the lifespan of the relinker.
  void AppendOrderer(Orderer* orderer);

  // Appends a list of orderers to be applied by this relinker.
  //
  // If no orderers are specified the default orderer will be applied. If no
  // transforms have been applied this makes the entire relinker an identity
  // relinker. Each orderer will be applied in the order added to the relinker,
  // assuming all earlier orderers have succeeded.
  //
  // @param orderers a vector of orderers to be applied to the input image.
  //     The pointers must remain valid for the lifespan of the relinker.
  void AppendOrderers(const std::vector<Orderer*>& orderers);

  // Appends a PDB mutator to be applied by this relinker.
  //
  // Each mutator will be applied in the order added to the relinker,
  // assuming all earlier mutators have succeeded.
  //
  // @param pdb_mutator a PDB mutator to be applied to the input image. The
  //     pointer must remain valid for the lifespan of the relinker.
  void AppendPdbMutator(pdb::PdbMutatorInterface* pdb_mutator);

  // Appends a list of PDB mutators to be applied by this relinker.
  //
  // Each mutator will be applied in the order added to the relinker,
  // assuming all earlier mutators have succeeded.
  //
  // @param pdb_mutators a vector of mutators to be applied to the input image.
  //     The pointers must remain valid for the lifespan of the relinker.
  void AppendPdbMutators(
      const std::vector<pdb::PdbMutatorInterface*>& pdb_mutators);

  // Runs the initialization phase of the relinker. This consists of decomposing
  // the input image, after which the intermediate data accessors declared below
  // become valid. This should typically be followed by a call to Relink.
  //
  // @returns true on success, false otherwise.
  // @pre input_path and output_path must be set prior to calling this.
  //     input_pdb_path and output_pdb_path may optionally have been set prior
  //     to calling this.
  // @post input_pe_file and input_image_layout may be called after this.
  // @note This entrypoint is virtual for unittest/mocking purposes.
  virtual bool Init();

  // Runs the relinker, generating an output image and PDB.
  //
  // @returns true on success, false otherwise.
  // @pre Init must have been called successfully.
  // @note This entrypoint is virtual for unittest/mocking purposes.
  virtual bool Relink();

  // @name Intermediate data accessors.
  // @{
  // These accessors only return meaningful data after Init has been called. By
  // the time any transforms or orderers are being called, these will contain
  // valid data.
  //
  // TODO(chrisha): Clean these up as part of the API simplification after
  //     all legacy code has been refactored.
  //
  // @pre Init has been successfully called.
  const PEFile& input_pe_file() const { return input_pe_file_; }
  const ImageLayout& input_image_layout() const { return input_image_layout_; }
  const BlockGraph& block_graph() const { return block_graph_; }
  const BlockGraph::Block* dos_header_block() const {
    return dos_header_block_; }
  const GUID& output_guid() const { return output_guid_; }
  // @}

 protected:
  FilePath input_path_;
  FilePath input_pdb_path_;
  FilePath output_path_;
  FilePath output_pdb_path_;

  // If true, metadata will be added to the output image. Defaults to true.
  bool add_metadata_;
  // If true, allow the relinker to rewrite the input files in place. Defaults
  // to false.
  bool allow_overwrite_;
  // If true, the PDB will be augmented with a serialized block-graph and
  // image layout. Defaults to true.
  bool augment_pdb_;
  // If true, then the augmented PDB stream will be compressed as it is written.
  // Defaults to false.
  bool compress_pdb_;
  // If true, then the decomposition will parse full symbol information.
  // Defaults to true.
  bool parse_debug_info_;
  // If true, strings associated with a block-graph will not be serialized into
  // the PDB. Defaults to false.
  bool strip_strings_;
  // If true we will use the new decomposer. Defaults to false.
  bool use_new_decomposer_;
  // Indicates the amount of padding to be added between blocks. Zero is the
  // default value and indicates no padding will be added.
  size_t padding_;

  // The vectors of user supplied transforms, orderers and mutators to be
  // applied.
  std::vector<Transform*> transforms_;
  std::vector<Orderer*> orderers_;
  std::vector<pdb::PdbMutatorInterface*> pdb_mutators_;

  // The internal state of the relinker.
  bool inited_;

  // Intermediate variables that are initialized and used by Relink. They are
  // made externally accessible so that transforms and orderers may make use
  // of them if necessary.

  // These refer to the original image, and don't change after init.
  PEFile input_pe_file_;
  ImageLayout input_image_layout_;

  // These refer to the image the whole way through the process. They may
  // evolve.
  BlockGraph block_graph_;
  BlockGraph::Block* dos_header_block_;

  // These are for the new image that will be produced at the end of Relink.
  GUID output_guid_;
};

}  // namespace pe

#endif  // SYZYGY_PE_PE_RELINKER_H_

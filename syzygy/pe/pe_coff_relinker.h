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
// The PECoffRelinker class serves as the base class of both PERelinker and
// CoffRelinker for common implementation routines.

#ifndef SYZYGY_PE_PE_COFF_RELINKER_H_
#define SYZYGY_PE_PE_COFF_RELINKER_H_

#include <vector>

#include "base/files/file_path.h"
#include "syzygy/block_graph/transform_policy.h"
#include "syzygy/pe/image_layout.h"
#include "syzygy/pe/relinker.h"

namespace pe {

// Base class for full file-to-file transformations of PE or COFF files;
// PERelinker and CoffRelinker extend this class. It provides implementation
// for common book-keeping routines for transforms and orderers.
class PECoffRelinker : public RelinkerInterface {
 public:
  typedef block_graph::BlockGraph BlockGraph;
  typedef block_graph::BlockGraphOrdererInterface Orderer;
  typedef block_graph::BlockGraphTransformInterface Transform;
  typedef block_graph::OrderedBlockGraph OrderedBlockGraph;
  typedef block_graph::TransformPolicyInterface TransformPolicyInterface;

  // Change the path to the main input file. By default, it is empty.
  //
  // @param input_path the new input path.
  void set_input_path(const base::FilePath& input_path) {
    input_path_ = input_path;
  }

  // Change the path to the main output file. By default, it is empty.
  //
  // @param output_path the new output path.
  void set_output_path(const base::FilePath& output_path) {
    output_path_ = output_path;
  }

  // Specify whether to allow output files to be overwritten. By default, it
  // is false. If @p allow_overwrite is true, input and output files may
  // overlap.
  //
  // @param allow_overwrite whether the output files may be overwritten.
  void set_allow_overwrite(bool allow_overwrite) {
    allow_overwrite_ = allow_overwrite;
  }

  // @returns the path to the main input file.
  const base::FilePath& input_path() const { return input_path_; }

  // @returns the path to the main output file.
  const base::FilePath& output_path() const { return output_path_; }

  // @returns whether output files may be overwritten.
  bool allow_overwrite() const { return allow_overwrite_; }

  // @see RelinkerInterface::AppendTransform()
  virtual bool AppendTransform(Transform* transform) OVERRIDE;

  // @see RelinkerInterface::AppendTransforms()
  virtual bool AppendTransforms(
      const std::vector<Transform*>& transforms) OVERRIDE;

  // @see RelinkerInterface::AppendOrderer()
  virtual bool AppendOrderer(Orderer* orderer) OVERRIDE;

  // @see RelinkerInterface::AppendOrderers()
  virtual bool AppendOrderers(const std::vector<Orderer*>& orderers) OVERRIDE;

  // The following accessors provide access to properties not initialized by
  // this class; they should be valid after the relinker has been
  // initialized in some fashion specific to the child class.
  // @{
  // After initialization, retrieve the original unmodified image layout.
  //
  // @returns the original image layout.
  const ImageLayout& input_image_layout() const {
    DCHECK(inited_);
    return input_image_layout_;
  }

  // After initialization, retrieve the block graph being processed; the
  // returned block graph will reflect changes made by passes.
  //
  // @returns the block graph.
  const BlockGraph& block_graph() const {
    DCHECK(inited_);
    return block_graph_;
  }

  // After initialization, retrieve the headers block being processed; the
  // returned block will reflect changes made by passes.
  //
  // @returns the headers block.
  const BlockGraph::Block* headers_block() const {
    DCHECK(inited_);
    return headers_block_;
  }
  // @}

 protected:
  // Construct a default PECoffRelinker. Initialize properties to default
  // values.
  // @param transform_policy The policy that dictates how to apply transforms.
  explicit PECoffRelinker(const TransformPolicyInterface* transform_policy);

  // Apply user-supplied transforms to the block graph
  // @returns true on success, or false on failure.
  bool ApplyUserTransforms();

  // Apply user-supplied orderers to the specified ordered block graph, or
  // the default original orderer if none has been added.
  // @param ordered_graph the ordered block graph to order or reorder.
  // @returns true on success, or false on failure.
  bool ApplyUserOrderers(OrderedBlockGraph* ordered_graph);

  // The policy that dictates how to apply transforms.
  const TransformPolicyInterface* transform_policy_;

  // The path to the main input file.
  base::FilePath input_path_;

  // The path to the main input file.
  base::FilePath output_path_;

  // Whether we may overwrite output files.
  bool allow_overwrite_;

  // Transforms to be applied, in order.
  std::vector<Transform*> transforms_;

  // Orderers to be applied, in order.
  std::vector<Orderer*> orderers_;

  // Whether the relinker has been initialized.
  bool inited_;

  // These refer to the original image, and don't change after init.
  ImageLayout input_image_layout_;

  // The block graph being processed. May be altered by user-supplied
  // passes.
  BlockGraph block_graph_;

  // The headers block of block_graph_.
  BlockGraph::Block* headers_block_;

 private:
  DISALLOW_COPY_AND_ASSIGN(PECoffRelinker);
};

}  // namespace pe

#endif  // SYZYGY_PE_PE_COFF_RELINKER_H_

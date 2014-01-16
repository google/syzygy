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
// Defines RelinkerInterface.

#ifndef SYZYGY_PE_RELINKER_H_
#define SYZYGY_PE_RELINKER_H_

#include <vector>

#include "base/logging.h"
#include "syzygy/block_graph/orderer.h"
#include "syzygy/block_graph/transform.h"
#include "syzygy/pdb/pdb_mutator.h"

namespace pe {

// Interface for full file-to-file transformations of PE or COFF files.
class RelinkerInterface {
 public:
  typedef block_graph::BlockGraph BlockGraph;
  typedef block_graph::BlockGraph::ImageFormat ImageFormat;
  typedef block_graph::BlockGraphOrdererInterface Orderer;
  typedef block_graph::BlockGraphTransformInterface Transform;
  typedef pdb::PdbMutatorInterface PdbMutator;

  // Virtual destructor for derived classes.
  virtual ~RelinkerInterface() {}

  // @returns the image format handled by the relinker.
  virtual ImageFormat image_format() const = 0;

  // Add a transform to be applied. Transform objects must outlive the
  // relinker. Each transform will be applied in the order added to the
  // relinker, assuming all earlier transforms have succeeded.
  //
  // @param transform a transform to be applied.
  // @returns true on success, or false if adding transforms is not
  //     supported.
  virtual bool AppendTransform(Transform* transform) {
    LOG(ERROR) << "Relinker does not support transforms.";
    return false;
  }

  // Add transforms to be applied. Transform objects must outlive the
  // relinker. Each transform will be applied in the order added to the
  // relinker, assuming all earlier transforms have succeeded.
  //
  // @param transforms transforms to be applied, in order.
  // @returns true on success, or false if adding transforms is not
  //     supported.
  virtual bool AppendTransforms(const std::vector<Transform*>& transforms) {
    LOG(ERROR) << "Relinker does not support transforms.";
    return false;
  }

  // Add an orderer to be applied. Orderer objects must outlive the
  // relinker. Each orderer will be applied in the order added to the
  // relinker, assuming all earlier orderers have succeeded.
  //
  // @param orderer an orderer to be applied.
  // @returns true on success, or false if adding orderers is not
  //     supported.
  virtual bool AppendOrderer(Orderer* orderer) {
    LOG(ERROR) << "Relinker does not support orderers.";
    return false;
  }

  // Add orderers to be applied. Orderer objects must outlive the
  // relinker. Each orderer will be applied in the order added to the
  // relinker, assuming all earlier orderers have succeeded.
  //
  // @param orderers orderers to be applied, in order.
  // @returns true on success, or false if adding orderers is not
  //     supported.
  virtual bool AppendOrderers(const std::vector<Orderer*>& orderers) {
    LOG(ERROR) << "Relinker does not support orderers.";
    return false;
  }

  // Add a PDB mutator to be applied. PDB mutater objects must outlive the
  // relinker. Each mutator will be applied in the order added to the
  // relinker, assuming all earlier mutators have succeeded.
  //
  // @param pdb_mutator a PDB mutator to be applied.
  // @returns true on success, or false if adding PDB mutators is not
  //     supported.
  virtual bool AppendPdbMutator(PdbMutator* pdb_mutator) {
    LOG(ERROR) << "Relinker does not support PDB mutators.";
    return false;
  }

  // Add PDB mutators to be applied by this relinker. Each mutator will be
  // applied in the order added to the relinker, assuming all earlier mutators
  // have succeeded.
  //
  // @param pdb_mutators a vector of mutators to be applied to the input image.
  //     The pointers must remain valid for the lifespan of the relinker.
  virtual bool AppendPdbMutators(const std::vector<PdbMutator*>& pdb_mutators) {
    LOG(ERROR) << "Relinker does not support PDB mutators.";
    return false;
  }

  // Initialize the relinker from its input data.
  //
  // @returns true on success, false otherwise.
  virtual bool Init() = 0;

  // After a successful call to Init(), apply transforms, orderers, and PDB
  // mutators, as appropriate, then generate the output files.
  //
  // @returns true on success, false otherwise.
  virtual bool Relink() = 0;

 protected:
  // Protected default constructor for derived classes.
  RelinkerInterface() {}

 private:
  DISALLOW_COPY_AND_ASSIGN(RelinkerInterface);
};

}  // namespace pe

#endif  // SYZYGY_PE_RELINKER_H_

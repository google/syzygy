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
// COFF relinker. Relinking can be seen as decomposing an input image,
// applying a sequence of block graph transforms (some applied implicitly,
// and others provided by the user), followed by a sequence of orderers
// (again, some implicit, some provided by the user), laying out, and
// writing a new image. CoffRelinker encapsulates this workflow.
//
// It is intended to be used as follows:
//
//   CoffRelinker relinker;
//   relinker.set_input_path(...);  // Required.
//   relinker.set_output_path(...);  // Required.
//   relinker.Init();  // Check the return value!
//
//   // At this point, the following accessors are valid:
//   relinker.input_image_file();
//   relinker.input_image_layout();
//   relinker.block_graph();
//   relinker.headers_block();
//
//   relinker.AppendTransform(...);  // May be called repeatedly.
//   relinker.AppendOrderer(...);  // May be called repeatedly.
//
//   relinker.Relink();  // Check the return value!

#ifndef SYZYGY_PE_COFF_RELINKER_H_
#define SYZYGY_PE_COFF_RELINKER_H_

#include "syzygy/pe/coff_file.h"
#include "syzygy/pe/coff_transform_policy.h"
#include "syzygy/pe/pe_coff_relinker.h"

namespace pe {

// A transformation on a COFF image, decomposing an original image, applying
// some transforms to it, generating the layout, and writing the new image
// to disk.
//
// Creating a CoffRelinker and not changing its default configuration yields
// an identity relinker that will produce a semantically identical image.
//
// The workflow is as follows:
//
// 1. The image is read and decomposed.
// 2. The image is transformed:
//    a) Transforms provided by the user are applied.
//    d) CoffPrepareHeadersTransform is applied.
// 3. The image is ordered by the user-specified orderers, or else by
//    OriginalOrderer if none is given.
// 4. CoffImageLayoutBuilder is used to convert the OrderedBlockGraph to an
//    ImageLayout.
// 5. The new image file is written.
class CoffRelinker : public PECoffRelinker {
 public:
  // Construct a default CoffRelinker. Initialize properties to default
  // values.
  // @param transform_policy The policy that dictates how to apply transforms.
  explicit CoffRelinker(const CoffTransformPolicy* transform_policy);

  // @see RelinkerInterface::image_format()
  virtual ImageFormat image_format() const OVERRIDE {
    return BlockGraph::COFF_IMAGE;
  }

  // Read and decompose the main input image, treated as a COFF file.
  //
  // @returns true on success, false otherwise.
  virtual bool Init() OVERRIDE;

  // After a successful call to Init(), apply transforms, followed by
  // orderers, then the resulting COFF file is written to the main output
  // path.
  //
  // @returns true on success, false otherwise.
  virtual bool Relink() OVERRIDE;

  // After a successful call to Init(), retrieve the original unmodified
  // COFF file reader.
  //
  // @returns the original COFF file reader.
  const CoffFile& input_image_file() const { return input_image_file_; }

 private:
  // Check paths for existence and overwriting validity.
  //
  // @returns true on success, or false on failure.
  bool CheckPaths();

  // The original COFF file reader.
  CoffFile input_image_file_;

  DISALLOW_COPY_AND_ASSIGN(CoffRelinker);
};

}  // namespace pe

#endif  // SYZYGY_PE_COFF_RELINKER_H_

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
// Declares the AddImportsOperation. This is effectively a wrapper for
// pe::AddImportsTransform.

#ifndef SYZYGY_PEHACKER_OPERATIONS_ADD_IMPORTS_OPERATION_H_
#define SYZYGY_PEHACKER_OPERATIONS_ADD_IMPORTS_OPERATION_H_

#include "base/memory/scoped_vector.h"
#include "syzygy/block_graph/transform.h"
#include "syzygy/pe/transforms/pe_add_imports_transform.h"
#include "syzygy/pehacker/operation.h"

namespace pehacker {
namespace operations {

class AddImportsOperation : public OperationInterface {
 public:
  AddImportsOperation() { }

  // Virtual destructor.
  virtual ~AddImportsOperation() { }

  // @name OperationInterface implementation.
  // @{
  virtual const char* name() const OVERRIDE;
  virtual bool Init(const TransformPolicyInterface* policy,
                    const base::DictionaryValue* operation);
  virtual bool Apply(const TransformPolicyInterface* policy,
                     BlockGraph* block_graph,
                     BlockGraph::Block* header_block);
  // @}

  // The name of this operation.
  static const char kName[];

 protected:
  typedef pe::transforms::ImportedModule ImportedModule;
  typedef std::map<std::string, ImportedModule*> ImportedModuleMap;

  // Unittesting seam.
  virtual bool ApplyTransform(block_graph::BlockGraphTransformInterface* tx,
                              const TransformPolicyInterface* policy,
                              BlockGraph* block_graph,
                              BlockGraph::Block* header_block);

  // The actual transform that will be applied.
  pe::transforms::PEAddImportsTransform add_imports_tx_;

  // The modules that will be imported.
  ScopedVector<ImportedModule> imported_modules_;
  ImportedModuleMap imported_module_map_;

 private:
  DISALLOW_COPY_AND_ASSIGN(AddImportsOperation);
};

}  // namespace operations
}  // namespace pehacker

#endif  // SYZYGY_PEHACKER_OPERATIONS_ADD_IMPORTS_OPERATION_H_

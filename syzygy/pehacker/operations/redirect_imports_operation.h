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
// Declares the RedirectImportsOperation. This is used by PEHacker to redirect
// any references from one import to another. The expected configuration for
// this operation has the form:
//
// {
//   'type': 'redirect_imports',
//   'redirects': [
//     {
//       'src': { 'module_name': 'foo.dll', 'function_name': 'foo' },
//       'dst': { 'module_name': 'bar.dll', 'function_name': 'bar' },
//     },
//     ... more redirects here
//   ],
// }
//
// The redirects will be applied in the order they are defined in the
// configuration. Null redirects (a -> a) will be ignored.

#ifndef SYZYGY_PEHACKER_OPERATIONS_REDIRECT_IMPORTS_OPERATION_H_
#define SYZYGY_PEHACKER_OPERATIONS_REDIRECT_IMPORTS_OPERATION_H_

#include "base/memory/scoped_vector.h"
#include "syzygy/block_graph/transform.h"
#include "syzygy/pe/transforms/pe_add_imports_transform.h"
#include "syzygy/pehacker/operation.h"

namespace pehacker {
namespace operations {

// An import redirection operation. Used to redirect references from one import
// to another.
class RedirectImportsOperation : public OperationInterface {
 public:
  RedirectImportsOperation() { }

  // Virtual destructor.
  virtual ~RedirectImportsOperation() { }

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

  // Unittesting seam.
  virtual bool ApplyTransform(block_graph::BlockGraphTransformInterface* tx,
                              const TransformPolicyInterface* policy,
                              BlockGraph* block_graph,
                              BlockGraph::Block* header_block);

  // Unittesting seam. This is called after the AddImportsTransform has
  // returned successfully and actually does the redirection.
  virtual bool RedirectImports();

  // Looks up a the imported module entry with the given name, creating one
  // and adding it to add_imports_tx_, imported_modules_ and
  // imported_module_map_ if it doesn't exist.
  ImportedModule* GetImportedModule(const std::string& module_name);

  // The actual transform that will be applied.
  pe::transforms::PEAddImportsTransform add_imports_tx_;

  // The import entries that will be looked up for redirection.
  typedef std::map<std::string, ImportedModule*> ImportedModuleMap;
  ScopedVector<ImportedModule> imported_modules_;
  ImportedModuleMap imported_module_map_;

  // This keeps track of configured mappings so that we can look up addresses
  // of entries.
  typedef std::pair<ImportedModule*, int> ImportedSymbol;
  typedef std::pair<ImportedSymbol, ImportedSymbol> RedirectedSymbol;
  typedef std::vector<RedirectedSymbol> RedirectedSymbols;
  RedirectedSymbols redirects_;

 private:
  DISALLOW_COPY_AND_ASSIGN(RedirectImportsOperation);
};

}  // namespace operations
}  // namespace pehacker

#endif  // SYZYGY_PEHACKER_OPERATIONS_REDIRECT_IMPORTS_OPERATION_H_

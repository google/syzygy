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

#include "syzygy/pehacker/operations/add_imports_operation.h"

#include "syzygy/block_graph/transform.h"

namespace pehacker {
namespace operations {

namespace {

using pe::transforms::ImportedModule;

static const char kFunctionName[] = "function_name";
static const char kMustNotExist[] = "must_not_exist";
static const char kOrdinal[] = "ordinal";

// A simple struct for representing content parsed from an 'add_import'
// operation.
struct ImportInfo {
  static const int kUnusedOrdinal = -1;
  std::string function_name;  // Empty if ordinal is being used.
  int ordinal;                // -1 if name is being used.
  bool must_not_exist;
};

// Parses a dictionary describing an import.
bool ParseImport(const base::DictionaryValue* import, ImportInfo* import_info) {
  DCHECK_NE(reinterpret_cast<const base::DictionaryValue*>(NULL), import);
  DCHECK_NE(reinterpret_cast<ImportInfo*>(NULL), import_info);

  bool have_function_name = import->HasKey(kFunctionName);
  bool have_ordinal = import->HasKey(kOrdinal);
  if (have_function_name && have_ordinal) {
    LOG(ERROR) << "Only one of \"" << kFunctionName << "\" or \""
               << kOrdinal << "\" may be defined in an import.";
    return false;
  }

  std::string function_name;
  if (have_function_name && !import->GetString(kFunctionName, &function_name)) {
    LOG(ERROR) << "\"" << kFunctionName << "\" must be a string.";
    return false;
  }

  int ordinal = -1;
  if (have_ordinal && !import->GetInteger(kOrdinal, &ordinal)) {
    LOG(ERROR) << "\"" << kOrdinal << "\" must be an integer.";
    return false;
  }

  bool must_not_exist = false;
  if (import->HasKey(kMustNotExist) &&
      !import->GetBoolean(kMustNotExist, &must_not_exist)) {
    LOG(ERROR) << "\"" << kMustNotExist << "\" must be a boolean.";
    return false;
  }

  import_info->function_name = function_name;
  import_info->ordinal = ordinal;
  import_info->must_not_exist = must_not_exist;

  return true;
}

}  // namespace

const char AddImportsOperation::kName[] = "AddImportsOperation";

const char* AddImportsOperation::name() const {
  return kName;
}

bool AddImportsOperation::Init(const TransformPolicyInterface* policy,
                               const base::DictionaryValue* operation) {
  DCHECK_NE(reinterpret_cast<TransformPolicyInterface*>(NULL), policy);
  DCHECK_NE(reinterpret_cast<base::DictionaryValue*>(NULL), operation);

  const base::ListValue* modules = NULL;
  if (!operation->GetList("modules", &modules)) {
    LOG(ERROR) << "Operation \"add_imports\" must contain a list of "
               << "\"modules\".";
    return false;
  }

  // Iterate over the modules to be imported.
  for (size_t i = 0; i < modules->GetSize(); ++i) {
    const base::DictionaryValue* module = NULL;
    if (!modules->GetDictionary(i, &module)) {
      LOG(ERROR) << "Each module must be a dictionary.";
      return false;
    }

    std::string module_name;
    if (!module->GetString("module_name", &module_name) ||
        module_name.empty()) {
      LOG(ERROR) << "Each module must contain a \"module_name\".";
      return false;
    }

    const base::ListValue* imports = NULL;
    if (!module->GetList("imports", &imports) || imports->empty()) {
      LOG(ERROR) << "Each module must contain a list of \"imports\".";
      return false;
    }

    bool must_not_exist = false;
    if (module->HasKey(kMustNotExist) &&
        !module->GetBoolean(kMustNotExist, &must_not_exist)) {
      LOG(ERROR) << "\"" << kMustNotExist << "\" must be a boolean.";
      return false;
    }

    // Get the imported module with this name. ImportModule objects aren't
    // copyable so we have to go out of our way to build a map of them.
    ImportedModuleMap::iterator mod_it =
        imported_module_map_.find(module_name);
    if (mod_it == imported_module_map_.end()) {
      ImportedModule* imported_module = new ImportedModule(module_name);
      imported_modules_.push_back(imported_module);
      mod_it = imported_module_map_.insert(std::make_pair(
          module_name, imported_module)).first;
    }

    // Iterate over the imports to be added from this module.
    for (size_t j = 0; j < imports->GetSize(); ++j) {
      const base::DictionaryValue* import = NULL;
      if (!imports->GetDictionary(j, &import)) {
        LOG(ERROR) << "Each import must be a dictionary.";
        return false;
      }

      ImportInfo import_info = {};
      if (!ParseImport(import, &import_info))
        return false;

      if (import_info.ordinal != ImportInfo::kUnusedOrdinal) {
        // TODO(chrisha): Add support for imports by ordinal.
        LOG(ERROR) << "Imports by ordinal are not currently supported.";
        return false;
      }

      // TODO(chrisha): Add support for a kMustImport mode.
      if (must_not_exist) {
        LOG(WARNING) << "The directive \"" << kMustNotExist << "\" is not yet "
                     << "supported.";
      }

      // Configure the import.
      VLOG(1) << "Parsed import \"" << module_name << ":"
              << import_info.function_name << "\".";
      mod_it->second->AddSymbol(
          import_info.function_name, ImportedModule::kAlwaysImport);
    }
  }

  // Configure the transform itself.
  ImportedModuleMap::iterator it = imported_module_map_.begin();
  for (; it != imported_module_map_.end(); ++it)
    add_imports_tx_.AddModule(it->second);

  return true;
}

bool AddImportsOperation::Apply(const TransformPolicyInterface* policy,
                                BlockGraph* block_graph,
                                BlockGraph::Block* header_block) {
  DCHECK_NE(reinterpret_cast<TransformPolicyInterface*>(NULL), policy);
  DCHECK_NE(reinterpret_cast<BlockGraph*>(NULL), block_graph);
  DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), header_block);

  // We pass our call through the unittesting seam so that we don't have to
  // actually run the transform on a decomposed image in our tests.
  VLOG(1) << "Applying \"" << add_imports_tx_.name() << "\" transform.";
  if (!ApplyTransform(&add_imports_tx_,
                      policy,
                      block_graph,
                      header_block)) {
    return false;
  }
  return true;
}

bool AddImportsOperation::ApplyTransform(
    block_graph::BlockGraphTransformInterface* tx,
    const TransformPolicyInterface* policy,
    BlockGraph* block_graph,
    BlockGraph::Block* header_block) {
  DCHECK_NE(reinterpret_cast<block_graph::BlockGraphTransformInterface*>(NULL),
            tx);
  DCHECK_NE(reinterpret_cast<TransformPolicyInterface*>(NULL), policy);
  DCHECK_NE(reinterpret_cast<BlockGraph*>(NULL), block_graph);
  DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), header_block);

  if (!block_graph::ApplyBlockGraphTransform(tx,
                                             policy,
                                             block_graph,
                                             header_block)) {
    return false;
  }
  return true;
}

}  // namespace operations
}  // namespace pehacker

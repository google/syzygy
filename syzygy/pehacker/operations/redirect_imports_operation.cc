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

#include "syzygy/pehacker/operations/redirect_imports_operation.h"

#include "syzygy/block_graph/transform.h"
#include "syzygy/pe/pe_utils.h"

namespace pehacker {
namespace operations {

namespace {

using block_graph::BlockGraph;
using pe::transforms::ImportedModule;

static const char kModuleName[] = "module_name";
static const char kFunctionName[] = "function_name";
static const char kOrdinal[] = "ordinal";

// A simple struct for representing content parsed from an 'redirect_import'
// operation.
struct ImportInfo {
  static const int kUnusedOrdinal = -1;
  std::string module_name;
  std::string function_name;  // Empty if ordinal is being used.
  int ordinal;                // -1 if name is being used.

  bool operator==(const ImportInfo& rhs) const {
    return module_name == rhs.module_name &&
        function_name == rhs.function_name &&
        ordinal == rhs.ordinal;
  }
};

// Parses a dictionary describing an import.
bool ParseImport(const base::DictionaryValue* import, ImportInfo* import_info) {
  DCHECK_NE(reinterpret_cast<const base::DictionaryValue*>(NULL), import);
  DCHECK_NE(reinterpret_cast<ImportInfo*>(NULL), import_info);

  std::string module_name;
  if (!import->GetString(kModuleName, &module_name)) {
    LOG(ERROR) << "Import must have a \"" << kModuleName << "\" string.";
    return false;
  }

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

  import_info->module_name = module_name;
  import_info->function_name = function_name;
  import_info->ordinal = ordinal;

  return true;
}

}  // namespace

const char RedirectImportsOperation::kName[] = "RedirectImportsOperation";

const char* RedirectImportsOperation::name() const {
  return kName;
}

bool RedirectImportsOperation::Init(const TransformPolicyInterface* policy,
                                    const base::DictionaryValue* operation) {
  DCHECK_NE(reinterpret_cast<TransformPolicyInterface*>(NULL), policy);
  DCHECK_NE(reinterpret_cast<base::DictionaryValue*>(NULL), operation);

  const base::ListValue* redirects = NULL;
  if (!operation->GetList("redirects", &redirects)) {
    LOG(ERROR) << "Operation \"redirect_imports\" must contain a list of "
               << "\"redirects\".";
    return false;
  }

  // Iterate over the redirects to be applied.
  for (size_t i = 0; i < redirects->GetSize(); ++i) {
    const base::DictionaryValue* redirect = NULL;
    if (!redirects->GetDictionary(i, &redirect)) {
      LOG(ERROR) << "Each redirect must be a dictionary.";
      return false;
    }

    // Get the import specification dictionaries.
    const base::DictionaryValue* src_dict = NULL;
    const base::DictionaryValue* dst_dict = NULL;
    if (!redirect->GetDictionary("src", &src_dict) ||
        !redirect->GetDictionary("dst", &dst_dict)) {
      LOG(ERROR) << "Each redirect must contain \"src\" and \"dst\" "
                 << "dictionaries.";
      return false;
    }

    // Parse the import dictionaries.
    ImportInfo src_info, dst_info;
    if (!ParseImport(src_dict, &src_info) || !ParseImport(dst_dict, &dst_info))
      return false;
    if (src_info.ordinal != ImportInfo::kUnusedOrdinal ||
        dst_info.ordinal != ImportInfo::kUnusedOrdinal) {
      LOG(ERROR) << "Ordinals are not yet supported.";
      return false;
    }

    // Silently ignore useless redirects.
    if (src_info == dst_info)
      continue;

    // Get transform configurations for each module.
    ImportedModule* src_mod = GetImportedModule(src_info.module_name);
    ImportedModule* dst_mod = GetImportedModule(dst_info.module_name);

    // Add the symbols and remember their indices.
    int src_index = src_mod->AddSymbol(src_info.function_name,
                                       ImportedModule::kFindOnly);
    int dst_index = dst_mod->AddSymbol(dst_info.function_name,
                                       ImportedModule::kFindOnly);

    // Record the redirection.
    ImportedSymbol src_sym(src_mod, src_index);
    ImportedSymbol dst_sym(dst_mod, dst_index);
    RedirectedSymbol redirected_symbol(src_sym, dst_sym);
    redirects_.push_back(redirected_symbol);
  }

  return true;
}

bool RedirectImportsOperation::Apply(const TransformPolicyInterface* policy,
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

  VLOG(1) << "Redirecting imports.";
  if (!RedirectImports())
    return false;

  return true;
}

bool RedirectImportsOperation::ApplyTransform(
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

bool RedirectImportsOperation::RedirectImports() {
  // Perform the redirections.
  std::set<pe::ReferenceDest> srcs, dsts;
  pe::ReferenceMap redirects;
  for (size_t i = 0; i < redirects_.size(); ++i) {
    const RedirectedSymbol& redirect = redirects_[i];
    const ImportedSymbol& src_sym = redirect.first;
    const ImportedSymbol& dst_sym = redirect.second;
    const ImportedModule* src_mod = src_sym.first;
    const ImportedModule* dst_mod = dst_sym.first;
    int src_index = src_sym.second;
    int dst_index = dst_sym.second;

    if (!src_mod->SymbolIsImported(src_index)) {
      LOG(ERROR) << "Failed to resolve \"src\" import \""
                 << src_mod->name() << ":"
                 << src_mod->GetSymbolName(src_index);
      return false;
    }
    if (!dst_mod->SymbolIsImported(dst_index)) {
      LOG(ERROR) << "Failed to resolve \"dst\" import \""
                 << dst_mod->name() << ":"
                 << dst_mod->GetSymbolName(dst_index);
      return false;
    }

    BlockGraph::Reference src_ref, dst_ref;
    CHECK(src_mod->GetSymbolReference(src_index, &src_ref));
    CHECK(dst_mod->GetSymbolReference(dst_index, &dst_ref));
    pe::ReferenceDest src(src_ref.referenced(), src_ref.offset());
    pe::ReferenceDest dst(dst_ref.referenced(), dst_ref.offset());

    // Ignore symbols that actually refer to the same thing. This can happen in
    // a way that we can't detect at configuration parsing time if a symbol is
    // referenced by name *and* by ordinal.
    if (src == dst) {
      VLOG(1) << "Ignoring redirect from a symbol to itself.";
      continue;
    }

    // A referenced location can not be both the source and destination of a
    // redirect in the same pass, as this defines a loop in the redirect
    // graph. Similarly, a source can not be repeated as (a -> b, a -> c) will
    // be applied as (a -> c), in violation of our stated guarantee that the
    // redirects will be applied in the exact order defined. A destination can
    // be multiply defined without any problems.
    if (dsts.count(src) || srcs.count(dst) || srcs.count(src)) {
      DCHECK_LT(0u, redirects.size());
      VLOG(1) << "Applying batch of reference redirections.";
      pe::RedirectReferences(redirects);
      srcs.clear();
      dsts.clear();
      redirects.clear();
    }

    VLOG(1) << "Configuring reference redirect from \""
            << src_mod->name() << ":" << src_mod->GetSymbolName(src_index)
            << "\" to \""
            << dst_mod->name() << ":" << dst_mod->GetSymbolName(dst_index)
            << "\".";
    redirects[src] = dst;
    srcs.insert(src);
    dsts.insert(dst);
  }

  // There will always be a final batch of redirections to apply.
  DCHECK_LT(0u, redirects.size());
  VLOG(1) << "Applying final batch of reference redirections.";
  pe::RedirectReferences(redirects);

  return true;
}

ImportedModule* RedirectImportsOperation::GetImportedModule(
    const std::string& module_name) {
  ImportedModuleMap::iterator mod_it =
      imported_module_map_.find(module_name);

  if (mod_it != imported_module_map_.end())
    return mod_it->second;

  ImportedModule* imported_module = new ImportedModule(module_name);
  imported_modules_.push_back(imported_module);
  mod_it = imported_module_map_.insert(std::make_pair(
      module_name, imported_module)).first;
  add_imports_tx_.AddModule(imported_module);

  return imported_module;
}

}  // namespace operations
}  // namespace pehacker

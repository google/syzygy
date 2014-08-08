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

#include "syzygy/instrument/transforms/asan_transform.h"

#include <vector>

#include "base/logging.h"
#include "base/rand_util.h"
#include "base/memory/ref_counted.h"
#include "base/memory/scoped_vector.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "syzygy/block_graph/basic_block.h"
#include "syzygy/block_graph/basic_block_assembler.h"
#include "syzygy/block_graph/block_builder.h"
#include "syzygy/block_graph/block_util.h"
#include "syzygy/block_graph/typed_block.h"
#include "syzygy/common/defs.h"
#include "syzygy/instrument/transforms/asan_intercepts.h"
#include "syzygy/pe/pe_utils.h"
#include "syzygy/pe/transforms/coff_add_imports_transform.h"
#include "syzygy/pe/transforms/coff_rename_symbols_transform.h"
#include "syzygy/pe/transforms/pe_add_imports_transform.h"
#include "third_party/distorm/files/include/mnemonics.h"
#include "third_party/distorm/files/src/x86defs.h"

namespace instrument {
namespace transforms {
namespace {

using block_graph::BasicBlock;
using block_graph::BasicCodeBlock;
using block_graph::BasicBlockAssembler;
using block_graph::BasicBlockSubGraph;
using block_graph::BasicBlockReference;
using block_graph::BlockBuilder;
using block_graph::BlockGraph;
using block_graph::Displacement;
using block_graph::Immediate;
using block_graph::Instruction;
using block_graph::Operand;
using block_graph::TransformPolicyInterface;
using block_graph::TypedBlock;
using block_graph::Value;
using block_graph::analysis::LivenessAnalysis;
using block_graph::analysis::MemoryAccessAnalysis;
using core::Register32;
using pe::transforms::CoffAddImportsTransform;
using pe::transforms::ImportedModule;
using pe::transforms::PEAddImportsTransform;

// A simple struct that can be used to let us access strings using TypedBlock.
struct StringStruct {
  const char string[1];
};

typedef AsanBasicBlockTransform::MemoryAccessMode AsanMemoryAccessMode;
typedef AsanBasicBlockTransform::AsanHookMap HookMap;
typedef std::vector<AsanBasicBlockTransform::AsanHookMapEntryKey>
    AccessHookParamVector;
typedef TypedBlock<IMAGE_IMPORT_DESCRIPTOR> ImageImportDescriptor;
typedef TypedBlock<StringStruct> String;

// The timestamp 1 corresponds to Thursday, 01 Jan 1970 00:00:01 GMT. Setting
// the timestamp of the image import descriptor to this value allows us to
// temporarily bind the library until the loader finishes loading this module.
// As the value is far in the past this means that the entries in the IAT for
// this module will all be replaced by pointers into the actual library.
// We need to bind the IAT for our module to make sure the stub is used until
// the sandbox lets the loader finish patching the IAT entries.
static const size_t kDateInThePast = 1;

// Returns true iff opcode should be instrumented.
bool ShouldInstrumentOpcode(uint16 opcode) {
  switch (opcode) {
    // LEA does not actually access memory.
    case I_LEA:
      return false;

    // We can ignore the prefetch and clflush instructions. The instrumentation
    // will detect memory errors if and when the memory is actually accessed.
    case I_CLFLUSH:
    case I_PREFETCH:
    case I_PREFETCHNTA:
    case I_PREFETCHT0:
    case I_PREFETCHT1:
    case I_PREFETCHT2:
    case I_PREFETCHW:
      return false;
  }
  return true;
}

// Computes the correct displacement, if any, for operand
// number @p operand of @p instr.
Displacement ComputeDisplacementForOperand(const Instruction& instr,
                                           size_t operand) {
  const _DInst& repr = instr.representation();

  DCHECK(repr.ops[operand].type == O_SMEM ||
         repr.ops[operand].type == O_MEM);

  size_t access_size_bytes = repr.ops[operand].size / 8;
  if (repr.dispSize == 0)
    return Displacement(access_size_bytes - 1);

  BasicBlockReference reference;
  if (instr.FindOperandReference(operand, &reference)) {
    if (reference.referred_type() == BasicBlockReference::REFERRED_TYPE_BLOCK) {
      return Displacement(reference.block(),
                          reference.offset() + access_size_bytes - 1);
    } else {
      return Displacement(reference.basic_block());
    }
  } else {
    return Displacement(repr.disp + access_size_bytes - 1);
  }
}

// Returns true if operand @p op is instrumentable, e.g.
// if it implies a memory access.
bool IsInstrumentable(const _Operand& op) {
  switch (op.type) {
    case O_SMEM:
    case O_MEM:
      return true;

    default:
      return false;
  }
}

// Returns true if opcode @p opcode is a special instruction.
// Memory checks for special instructions (string instructions, instructions
// with prefix, etc) are handled by calling specialized functions rather than
// the standard memory checks.
bool IsSpecialInstruction(uint16_t opcode) {
  switch (opcode) {
    case I_CMPS:
    case I_STOS:
    case I_MOVS:
      return true;

    default:
      return false;
  }
}

// Decodes the first O_MEM or O_SMEM operand of @p instr, if any to the
// corresponding Operand.
bool DecodeMemoryAccess(const Instruction& instr,
    Operand* access,
    AsanBasicBlockTransform::MemoryAccessInfo* info) {
  DCHECK(access != NULL);
  DCHECK(info != NULL);
  const _DInst& repr = instr.representation();

  // Figure out which operand we're instrumenting.
  size_t mem_op_id = -1;
  if (IsInstrumentable(repr.ops[0]) && IsInstrumentable(repr.ops[1])) {
    // This happens with instructions like: MOVS [EDI], [ESI].
    DCHECK(repr.ops[0].size == repr.ops[1].size);
    mem_op_id = 0;
  } else if (IsInstrumentable(repr.ops[0])) {
    // The first operand is instrumentable.
    mem_op_id = 0;
  } else if (IsInstrumentable(repr.ops[1])) {
    // The second operand is instrumentable.
    mem_op_id = 1;
  } else {
    // Neither of the first two operands is instrumentable.
    return false;
  }

  // Determine the size of the access.
  info->size = repr.ops[mem_op_id].size / 8;

  // Determine the kind of access (read/write/instr/repz).
  if (FLAG_GET_PREFIX(repr.flags) & FLAG_REPNZ) {
    info->mode = AsanBasicBlockTransform::kRepnzAccess;
  } else if (FLAG_GET_PREFIX(repr.flags) & FLAG_REP) {
    info->mode = AsanBasicBlockTransform::kRepzAccess;
  } else if (IsSpecialInstruction(instr.opcode())) {
    info->mode = AsanBasicBlockTransform::kInstrAccess;
  } else if ((repr.flags & FLAG_DST_WR) && mem_op_id == 0) {
    // The first operand is written to.
    info->mode = AsanBasicBlockTransform::kWriteAccess;
  } else {
    info->mode = AsanBasicBlockTransform::kReadAccess;
  }

  // Determine the opcode of this instruction (when needed).
  if (info->mode == AsanBasicBlockTransform::kRepnzAccess ||
      info->mode == AsanBasicBlockTransform::kRepzAccess ||
      info->mode == AsanBasicBlockTransform::kInstrAccess) {
    info->opcode = instr.opcode();
  }

  // Determine operand of the access.
  if (repr.ops[mem_op_id].type == O_SMEM) {
    // Simple memory dereference with optional displacement.
    const Register32& base_reg = core::CastAsRegister32(
        core::GetRegister(repr.ops[mem_op_id].index));

    // Get the displacement for the operand.
    Displacement displ = ComputeDisplacementForOperand(instr, mem_op_id);
    *access = Operand(base_reg, displ);
  } else if (repr.ops[0].type == O_MEM || repr.ops[1].type == O_MEM) {
    // Complex memory dereference.
    const Register32& index_reg = core::CastAsRegister32(
        core::GetRegister(repr.ops[mem_op_id].index));

    core::ScaleFactor scale = core::kTimes1;
    switch (repr.scale) {
      case 2:
        scale = core::kTimes2;
        break;
      case 4:
        scale = core::kTimes4;
        break;
      case 8:
        scale = core::kTimes8;
        break;
      default:
        break;
    }

    // Get the displacement for the operand (if any).
    Displacement displ = ComputeDisplacementForOperand(instr, mem_op_id);

    // Compute the full operand.
    if (repr.base != R_NONE) {
      const Register32& base_reg = core::CastAsRegister32(
          core::GetRegister(repr.base));

      if (displ.size() == core::kSizeNone) {
        // No displacement, it's a [base + index * scale] access.
        *access = Operand(base_reg, index_reg, scale);
      } else {
        // This is a [base + index * scale + displ] access.
        *access = Operand(base_reg, index_reg, scale, displ);
      }
    } else {
      // No base, this is an [index * scale + displ] access.
      // TODO(siggi): AFAIK, there's no encoding for [index * scale] without
      //    a displacement. If this assert fires, I'm proven wrong.
      DCHECK_NE(core::kSizeNone, displ.size());

      *access = Operand(index_reg, scale, displ);
    }
  } else {
    NOTREACHED();
    return false;
  }

  return true;
}

// Use @p bb_asm to inject a hook to @p hook to instrument the access to the
// address stored in the operand @p op.
void InjectAsanHook(BasicBlockAssembler* bb_asm,
                    const AsanBasicBlockTransform::MemoryAccessInfo& info,
                    const Operand& op,
                    BlockGraph::Reference* hook,
                    const LivenessAnalysis::State& state,
                    BlockGraph::ImageFormat image_format) {
  DCHECK(hook != NULL);

  // Determine which kind of probe to inject.
  //   - The standard load/store probe assume the address is in EDX.
  //     It restore the original version of EDX and cleanup the stack.
  //   - The special instruction probe take addresses directly in registers.
  //     The probe doesn't have any effects on stack, registers and flags.
  if (info.mode == AsanBasicBlockTransform::kReadAccess ||
      info.mode == AsanBasicBlockTransform::kWriteAccess) {
    // Load/store probe.
    bb_asm->push(core::edx);
    bb_asm->lea(core::edx, op);
  }

  // Call the hook.
  Displacement displ(hook->referenced(), hook->offset());
  if (image_format == BlockGraph::PE_IMAGE) {
    // In PE images the hooks are brought in as imports, so they are indirect
    // references.
    bb_asm->call(Operand(displ));
  } else {
    DCHECK_EQ(BlockGraph::COFF_IMAGE, image_format);
    // In COFF images the hooks are brought in as symbols, so they are direct
    // references.
    bb_asm->call(displ);
  }
}

// Get the name of an asan check access function for an @p access_mode access.
// @param info The memory access information, e.g. the size on a load/store,
//     the instruction opcode and the kind of access.
std::string GetAsanCheckAccessFunctionName(
    AsanBasicBlockTransform::MemoryAccessInfo info,
    BlockGraph::ImageFormat image_format) {
  DCHECK(info.mode != AsanBasicBlockTransform::kNoAccess);
  DCHECK_NE(0U, info.size);
  DCHECK(info.mode == AsanBasicBlockTransform::kReadAccess ||
         info.mode == AsanBasicBlockTransform::kWriteAccess ||
         info.opcode != 0);

  const char* rep_str = NULL;
  if (info.mode == AsanBasicBlockTransform::kRepzAccess)
    rep_str = "_repz";
  else if (info.mode == AsanBasicBlockTransform::kRepnzAccess)
    rep_str = "_repnz";
  else
    rep_str = "";

  const char* access_mode_str = NULL;
  if (info.mode == AsanBasicBlockTransform::kReadAccess)
    access_mode_str = "read";
  else if (info.mode == AsanBasicBlockTransform::kWriteAccess)
    access_mode_str = "write";
  else
    access_mode_str = reinterpret_cast<char*>(GET_MNEMONIC_NAME(info.opcode));

  // For COFF images we use the decorated function name, which contains a
  // leading underscore.
  std::string function_name =
      base::StringPrintf("%sasan_check%s_%d_byte_%s_access%s",
                         image_format == BlockGraph::PE_IMAGE ? "" : "_",
                         rep_str,
                         info.size,
                         access_mode_str,
                         info.save_flags ? "" : "_no_flags");
  StringToLowerASCII(&function_name);
  return function_name;
}

// Add imports from the specified module to the block graph, altering the
// contents of its header/special blocks.
// @param policy the policy object restricting how the transform is applied.
// @param block_graph the block graph to modify.
// @param header_block the header block of @p block_graph.
// @param module the module to import, with its symbols.
// @returns true on success, or false on failure.
bool AddImportsFromModule(const TransformPolicyInterface* policy,
                          BlockGraph* block_graph,
                          BlockGraph::Block* header_block,
                          ImportedModule* module) {
  if (block_graph->image_format() == BlockGraph::PE_IMAGE) {
    PEAddImportsTransform transform;
    transform.AddModule(module);
    if (!ApplyBlockGraphTransform(&transform, policy,
                                  block_graph, header_block)) {
      return false;
    }
  } else {
    DCHECK_EQ(BlockGraph::COFF_IMAGE, block_graph->image_format());
    CoffAddImportsTransform transform;
    transform.AddModule(module);
    if (!ApplyBlockGraphTransform(&transform, policy,
                                  block_graph, header_block)) {
      return false;
    }
  }

  return true;
}

// Add the imports for the asan check access hooks to the block-graph.
// @param hooks_param_vector A vector of hook parameter values.
// @param default_stub_map Stubs for the asan check access functions.
// @param import_module The module for which the import should be added.
// @param check_access_hook_map The map where the reference to the imports
//     should be stored.
// @param policy The policy object restricting how the transform is applied.
// @param block_graph The block-graph to populate.
// @param header_block The block containing the module's DOS header of this
//     block-graph.
// @returns True on success, false otherwise.
bool AddAsanCheckAccessHooks(
    const AccessHookParamVector& hook_param_vector,
    const AsanBasicBlockTransform::AsanDefaultHookMap& default_stub_map,
    ImportedModule* import_module,
    HookMap* check_access_hook_map,
    const TransformPolicyInterface* policy,
    BlockGraph* block_graph,
    BlockGraph::Block* header_block) {
  DCHECK(import_module != NULL);
  DCHECK(check_access_hook_map != NULL);
  DCHECK(policy != NULL);
  DCHECK(block_graph != NULL);
  DCHECK(header_block != NULL);

  typedef std::map<AsanBasicBlockTransform::AsanHookMapEntryKey, size_t>
      HooksParamsToIdxMap;
  HooksParamsToIdxMap hooks_params_to_idx;

  // Add the hooks to the import module.
  AccessHookParamVector::const_iterator iter_params = hook_param_vector.begin();
  for (; iter_params != hook_param_vector.end(); ++iter_params) {
    size_t symbol_idx = import_module->AddSymbol(
        GetAsanCheckAccessFunctionName(*iter_params,
                                       block_graph->image_format()),
        ImportedModule::kAlwaysImport);
    hooks_params_to_idx[*iter_params] = symbol_idx;
  }

  DCHECK_EQ(hooks_params_to_idx.size(), hook_param_vector.size());

  // Add the imports. This takes care of invoking the appropriate format
  // specific transform.
  if (!AddImportsFromModule(policy, block_graph, header_block, import_module)) {
    LOG(ERROR) << "Unable to add imports for Asan instrumentation DLL.";
    return false;
  }

  // Get a reference to each hook and put it in the hooks map.
  HooksParamsToIdxMap::iterator iter_hooks = hooks_params_to_idx.begin();
  for (; iter_hooks != hooks_params_to_idx.end(); ++iter_hooks) {
    BlockGraph::Reference import_reference;
    if (!import_module->GetSymbolReference(iter_hooks->second,
                                           &import_reference)) {
      LOG(ERROR) << "Unable to get import reference for Asan.";
      return false;
    }
    HookMap& hook_map = *check_access_hook_map;
    hook_map[iter_hooks->first] = import_reference;

    // We only need dummy implementation stubs for PE images, as the hooks are
    // imported. COFF instrumented images contain the hooks directly.
    if (block_graph->image_format() == BlockGraph::PE_IMAGE) {
      // In a Chrome sandboxed process the NtMapViewOfSection function is
      // intercepted by the sandbox agent. This causes execution in the
      // executable before imports have been resolved, as the ntdll patch
      // invokes into the executable while resolving imports. As the Asan
      // instrumentation directly refers to the IAT entries we need to
      // temporarily stub these function until the Asan imports are resolved. To
      // do this we need to make the IAT entries for those functions point to a
      // temporarily block and we need to mark the image import descriptor for
      // this DLL as bound.
      AsanBasicBlockTransform::AsanDefaultHookMap::const_iterator
          stub_reference = default_stub_map.find(iter_hooks->first.mode);
      if (stub_reference == default_stub_map.end()) {
         LOG(ERROR) << "Could not find the default hook for "
                    << GetAsanCheckAccessFunctionName(iter_hooks->first,
                                                      BlockGraph::PE_IMAGE)
                    << ".";
        return false;
      }

      import_reference.referenced()->SetReference(import_reference.offset(),
                                                  stub_reference->second);
    }
  }

  return true;
}

// Create a stub for the asan_check_access functions. For load/store, the stub
// consists of a small block of code that restores the value of EDX and returns
// to the caller. Otherwise, the stub do return.
// @param block_graph The block-graph to populate with the stub.
// @param stub_name The stub's name.
// @param mode The kind of memory access.
// @param reference Will receive the reference to the created hook.
// @returns true on success, false otherwise.
bool CreateHooksStub(BlockGraph* block_graph,
                     const base::StringPiece& stub_name,
                     AsanBasicBlockTransform::MemoryAccessMode mode,
                     BlockGraph::Reference* reference) {
  DCHECK(reference != NULL);

  // Find or create the section we put our thunks in.
  BlockGraph::Section* thunk_section = block_graph->FindOrAddSection(
      common::kThunkSectionName, pe::kCodeCharacteristics);

  if (thunk_section == NULL) {
    LOG(ERROR) << "Unable to find or create .thunks section.";
    return false;
  }

  std::string stub_name_with_id = base::StringPrintf(
      "%.*s%d", stub_name.length(), stub_name.data(), mode);

  // Create the thunk for standard "load/store" (received address in EDX).
  BasicBlockSubGraph bbsg;
  BasicBlockSubGraph::BlockDescription* block_desc = bbsg.AddBlockDescription(
      stub_name_with_id,
      thunk_section->name(),
      BlockGraph::CODE_BLOCK,
      thunk_section->id(),
      1,
      0);

  BasicCodeBlock* bb = bbsg.AddBasicCodeBlock(stub_name_with_id);
  block_desc->basic_block_order.push_back(bb);
  BasicBlockAssembler assm(bb->instructions().begin(), &bb->instructions());

  if (mode == AsanBasicBlockTransform::kReadAccess ||
      mode == AsanBasicBlockTransform::kWriteAccess) {
    // The thunk body restores the original value of EDX and cleans the stack on
    // return.
    assm.mov(core::edx, Operand(core::esp, Displacement(4)));
    assm.ret(4);
  } else {
    assm.ret();
  }

  // Condense into a block.
  BlockBuilder block_builder(block_graph);
  if (!block_builder.Merge(&bbsg)) {
    LOG(ERROR) << "Failed to build thunk block.";
    return NULL;
  }

  // Exactly one new block should have been created.
  DCHECK_EQ(1u, block_builder.new_blocks().size());
  BlockGraph::Block* thunk = block_builder.new_blocks().front();

  *reference = BlockGraph::Reference(BlockGraph::ABSOLUTE_REF, 4, thunk, 0, 0);

  return true;
}

typedef std::map<std::string, size_t> ImportNameIndexMap;

bool PeFindImportsToIntercept(bool use_interceptors,
                              const AsanIntercept* intercepts,
                              const TransformPolicyInterface* policy,
                              BlockGraph* block_graph,
                              BlockGraph::Block* header_block,
                              ScopedVector<ImportedModule>* imported_modules,
                              ImportNameIndexMap* import_name_index_map,
                              ImportedModule* asan_rtl) {
  DCHECK_NE(reinterpret_cast<AsanIntercept*>(NULL), intercepts);
  DCHECK_NE(reinterpret_cast<TransformPolicyInterface*>(NULL), policy);
  DCHECK_NE(reinterpret_cast<BlockGraph*>(NULL), block_graph);
  DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), header_block);
  DCHECK_NE(reinterpret_cast<ScopedVector<ImportedModule>*>(NULL),
            imported_modules);
  DCHECK_NE(reinterpret_cast<ImportNameIndexMap*>(NULL), import_name_index_map);
  DCHECK_NE(reinterpret_cast<ImportedModule*>(NULL), asan_rtl);

  // Process all of the import intercepts.
  PEAddImportsTransform find_imports;
  ImportedModule* current_module = NULL;
  const char* current_module_name = NULL;
  const AsanIntercept* intercept = intercepts;
  for (; intercept->undecorated_name != NULL; ++intercept) {
    // Create a new module to house these imports.
    if (intercept->module != current_module_name) {
      current_module_name = intercept->module;
      current_module = NULL;
      if (current_module_name) {
        current_module = new ImportedModule(current_module_name);
        imported_modules->push_back(current_module);
        find_imports.AddModule(current_module);
      }
    }

    // If no module name is specified then this interception is not an import
    // interception.
    if (current_module_name == NULL)
      continue;

    // Don't process optional intercepts unless asked to.
    if (!use_interceptors && intercept->optional)
      continue;

    current_module->AddSymbol(intercept->undecorated_name,
                              ImportedModule::kFindOnly);
  }

  // Query the imports to see which ones are present.
  if (!find_imports.TransformBlockGraph(
          policy, block_graph, header_block)) {
    LOG(ERROR) << "Unable to find imports for redirection.";
    return false;
  }

  // Add ASAN imports for those functions found in the import tables. These will
  // later be redirected.
  for (size_t i = 0; i < imported_modules->size(); ++i) {
    ImportedModule* module = (*imported_modules)[i];
    for (size_t j = 0; j < module->size(); ++j) {
      if (!module->SymbolIsImported(j))
        continue;

      // The function should not already be imported. If it is then the
      // intercepts data contains duplicates.
      const std::string& function_name = module->GetSymbolName(j);
      DCHECK(import_name_index_map->find(function_name) ==
                 import_name_index_map->end());

      std::string asan_function_name = kUndecoratedAsanInterceptPrefix;
      asan_function_name += function_name;
      size_t index = asan_rtl->AddSymbol(asan_function_name,
                                         ImportedModule::kAlwaysImport);
      import_name_index_map->insert(std::make_pair(function_name, index));
    }
  }

  return true;
}

void PeFindStaticallyLinkedFunctionsToIntercept(
    bool use_interceptors,
    const AsanIntercept* intercepts,
    BlockGraph* block_graph,
    std::vector<BlockGraph::Block*>* static_blocks,
    ImportNameIndexMap* import_name_index_map,
    ImportedModule* asan_rtl) {
  DCHECK_NE(reinterpret_cast<AsanIntercept*>(NULL), intercepts);
  DCHECK_NE(reinterpret_cast<BlockGraph*>(NULL), block_graph);
  DCHECK_NE(reinterpret_cast<std::vector<BlockGraph::Block*>*>(NULL),
            static_blocks);
  DCHECK_NE(reinterpret_cast<ImportNameIndexMap*>(NULL), import_name_index_map);
  DCHECK_NE(reinterpret_cast<ImportedModule*>(NULL), asan_rtl);

  // Populate the filter with known hashes.
  AsanInterceptorFilter filter;
  filter.InitializeContentHashes(intercepts, use_interceptors);
  if (filter.empty())
    return;

  // Discover statically linked functions that need to be intercepted.
  BlockGraph::BlockMap::iterator block_it =
      block_graph->blocks_mutable().begin();
  for (; block_it != block_graph->blocks_mutable().end(); ++block_it) {
    BlockGraph::Block* block = &block_it->second;
    if (!filter.ShouldIntercept(block))
      continue;
    static_blocks->push_back(block);

    // Don't add an import entry for names that have already been processed.
    if (import_name_index_map->find(block->name()) !=
            import_name_index_map->end()) {
      continue;
    }

    std::string name = kUndecoratedAsanInterceptPrefix;
    name += block->name();
    size_t index = asan_rtl->AddSymbol(name,
                                      ImportedModule::kAlwaysImport);
    import_name_index_map->insert(std::make_pair(block->name(), index));
  }
}

void PeGetRedirectsForInterceptedImports(
    const ScopedVector<ImportedModule>& imported_modules,
    const ImportNameIndexMap& import_name_index_map,
    const ImportedModule& asan_rtl,
    pe::ReferenceMap* reference_redirect_map) {
  DCHECK_NE(reinterpret_cast<pe::ReferenceMap*>(NULL), reference_redirect_map);

  // Register redirections related to the original.
  for (size_t i = 0, k = 0; i < imported_modules.size(); ++i) {
    const ImportedModule* module = imported_modules[i];
    for (size_t j = 0; j < module->size(); ++j) {
      if (!module->SymbolIsImported(j))
        continue;

      // Get a reference to the original import.
      BlockGraph::Reference src;
      CHECK(module->GetSymbolReference(j, &src));

      // Get a reference to the newly created import.
      const std::string& name = module->GetSymbolName(j);
      ImportNameIndexMap::const_iterator import_it =
          import_name_index_map.find(name);
      DCHECK(import_it != import_name_index_map.end());
      BlockGraph::Reference dst;
      CHECK(asan_rtl.GetSymbolReference(import_it->second, &dst));

      // Record the reference mapping.
      reference_redirect_map->insert(
          std::make_pair(pe::ReferenceDest(src.referenced(), src.offset()),
                         pe::ReferenceDest(dst.referenced(), dst.offset())));
    }
  }
}

bool PeGetRedirectsForStaticallyLinkedFunctions(
    const std::vector<BlockGraph::Block*>& static_blocks,
    const ImportNameIndexMap& import_name_index_map,
    const ImportedModule& asan_rtl,
    BlockGraph* block_graph,
    pe::ReferenceMap* reference_redirect_map) {
  DCHECK_NE(reinterpret_cast<BlockGraph*>(NULL), block_graph);
  DCHECK_NE(reinterpret_cast<pe::ReferenceMap*>(NULL), reference_redirect_map);

  BlockGraph::Section* thunk_section = block_graph->FindOrAddSection(
      common::kThunkSectionName, pe::kCodeCharacteristics);
  DCHECK_NE(reinterpret_cast<BlockGraph::Section*>(NULL), thunk_section);

  typedef std::map<std::string, BlockGraph::Block*> ThunkMap;
  ThunkMap thunk_map;
  for (size_t i = 0; i < static_blocks.size(); ++i) {
    BlockGraph::Block* block = static_blocks[i];

    ThunkMap::iterator thunk_it = thunk_map.find(block->name());
    if (thunk_it == thunk_map.end()) {
      // Generate the name of the thunk for this function.
      std::string thunk_name = kUndecoratedAsanInterceptPrefix;
      thunk_name += block->name();
      thunk_name += "_thunk";

      // Get a reference to the newly created import.
      ImportNameIndexMap::const_iterator import_it =
          import_name_index_map.find(block->name());
      DCHECK(import_it != import_name_index_map.end());
      BlockGraph::Reference import_ref;
      CHECK(asan_rtl.GetSymbolReference(import_it->second, &import_ref));

      // Generate a basic code block for this thunk.
      BasicBlockSubGraph bbsg;
      BasicBlockSubGraph::BlockDescription* block_desc =
          bbsg.AddBlockDescription(thunk_name,
                                   thunk_section->name(),
                                   BlockGraph::CODE_BLOCK,
                                   thunk_section->id(),
                                   1,
                                   0);

      BasicCodeBlock* bb = bbsg.AddBasicCodeBlock(thunk_name);
      block_desc->basic_block_order.push_back(bb);
      BasicBlockAssembler assm(bb->instructions().begin(),
                               &bb->instructions());
      assm.jmp(Operand(Displacement(import_ref.referenced(),
                                    import_ref.offset())));

      // Condense into a block.
      BlockBuilder block_builder(block_graph);
      if (!block_builder.Merge(&bbsg)) {
        LOG(ERROR) << "Failed to build thunk block \"" << thunk_name << "\".";
        return false;
      }

      // Exactly one new block should have been created.
      DCHECK_EQ(1u, block_builder.new_blocks().size());
      BlockGraph::Block* thunk = block_builder.new_blocks().front();
      thunk_it = thunk_map.insert(std::make_pair(block->name(), thunk)).first;
    }
    DCHECK(thunk_it != thunk_map.end());

    // Register a redirection of references, from the original block to the
    // newly created thunk.
    reference_redirect_map->insert(std::make_pair(
        pe::ReferenceDest(block, 0),
        pe::ReferenceDest(thunk_it->second, 0)));
  }

  return true;
}

}  // namespace

const char AsanBasicBlockTransform::kTransformName[] =
    "SyzyAsanBasicBlockTransform";

bool AsanBasicBlockTransform::InstrumentBasicBlock(
    BasicCodeBlock* basic_block,
    StackAccessMode stack_mode,
    BlockGraph::ImageFormat image_format) {
  DCHECK_NE(reinterpret_cast<BasicCodeBlock*>(NULL), basic_block);

  if (instrumentation_rate_ == 0.0)
    return true;

  // Pre-compute liveness information for each instruction.
  std::list<LivenessAnalysis::State> states;
  LivenessAnalysis::State state;
  if (use_liveness_analysis_) {
    liveness_.GetStateAtExitOf(basic_block, &state);

    BasicBlock::Instructions::reverse_iterator rev_iter_inst =
        basic_block->instructions().rbegin();
    BasicBlock::Instructions::const_reverse_iterator rev_iter_inst_end =
        basic_block->instructions().rend();
    for (; rev_iter_inst != rev_iter_inst_end; ++rev_iter_inst) {
      const Instruction& instr = *rev_iter_inst;
      liveness_.PropagateBackward(instr, &state);
      states.push_front(state);
    }

    DCHECK_EQ(states.size(), basic_block->instructions().size());
  }

  // Get the memory accesses information for this basic block.
  MemoryAccessAnalysis::State memory_state;
  if (remove_redundant_checks_)
    memory_accesses_.GetStateAtEntryOf(basic_block, &memory_state);

  // Process each instruction and inject a call to Asan when we find an
  // instrumentable memory access.
  BasicBlock::Instructions::iterator iter_inst =
      basic_block->instructions().begin();
  std::list<LivenessAnalysis::State>::iterator iter_state = states.begin();
  for (; iter_inst != basic_block->instructions().end(); ++iter_inst) {
    Operand operand(core::eax);
    const Instruction& instr = *iter_inst;
    const _DInst& repr = instr.representation();

    MemoryAccessInfo info;
    info.mode = kNoAccess;
    info.size = 0;
    info.opcode = 0;
    info.save_flags = true;

    // Get current instruction liveness information.
    if (use_liveness_analysis_) {
      state = *iter_state;
      ++iter_state;
    }

    // When activated, skip redundant memory access check.
    if (remove_redundant_checks_) {
      bool need_memory_access_check = false;
      if (memory_state.HasNonRedundantAccess(instr))
        need_memory_access_check = true;

      // Update the memory accesses information for the current instruction.
      memory_accesses_.PropagateForward(instr, &memory_state);

      if (!need_memory_access_check)
        continue;
    }

    // Insert hook for a standard instruction.
    if (!DecodeMemoryAccess(instr, &operand, &info))
      continue;

    // Bail if this is not a memory access.
    if (info.mode == kNoAccess)
      continue;

    // A basic block reference means that can be either a computed jump,
    // or a load from a case table. In either case it doesn't make sense
    // to instrument the access.
    if (operand.displacement().reference().referred_type() ==
        BasicBlockReference::REFERRED_TYPE_BASIC_BLOCK) {
      continue;
    }

    // A block reference means this instruction is reading or writing to
    // a global variable or some such. It's viable to pad and align global
    // variables and to red-zone the padding, but without that, there's nothing
    // to gain by instrumenting these accesses.
    if (operand.displacement().reference().referred_type() ==
        BasicBlockReference::REFERRED_TYPE_BLOCK) {
      continue;
    }

    // Is this an instruction we should be instrumenting.
    if (!ShouldInstrumentOpcode(repr.opcode))
      continue;

    // If there are no unconventional manipulations of the stack frame, we can
    // skip instrumenting stack-based memory access (based on ESP or EBP).
    // Conventionally, accesses through ESP/EBP are always on stack.
    if (stack_mode == kSafeStackAccess &&
        (operand.base() == core::kRegisterEsp ||
         operand.base() == core::kRegisterEbp)) {
      continue;
    }

    // We do not instrument memory accesses through special segments.
    // FS is used for thread local specifics and GS for CPU info.
    uint8_t segment = SEGMENT_GET(repr.segment);
    if (segment == R_FS || segment == R_GS)
      continue;

    // Don't instrument any filtered instructions.
    if (IsFiltered(*iter_inst))
      continue;

    // Randomly sample to effect partial instrumentation.
    if (instrumentation_rate_ < 1.0 &&
        base::RandDouble() >= instrumentation_rate_) {
      continue;
    }

    // Create a BasicBlockAssembler to insert new instruction.
    BasicBlockAssembler bb_asm(iter_inst, &basic_block->instructions());

    // Configure the assembler to copy the SourceRange information of the
    // current instrumented instruction into newly created instructions. This is
    // a hack to allow valid stack walking and better error reporting, but
    // breaks the 1:1 OMAP mapping and may confuse some debuggers.
    if (debug_friendly_)
      bb_asm.set_source_range(instr.source_range());

    if (use_liveness_analysis_ &&
        (info.mode == kReadAccess || info.mode == kWriteAccess)) {
      // Use the liveness information to skip saving the flags if possible.
      info.save_flags = state.AreArithmeticFlagsLive();
    }

    // Insert hook for standard instructions.
    AsanHookMap::iterator hook = check_access_hooks_->find(info);
    if (hook == check_access_hooks_->end()) {
      LOG(ERROR) << "Invalid access : "
                 << GetAsanCheckAccessFunctionName(info, image_format);
      return false;
    }

    // Instrument this instruction.
    InjectAsanHook(&bb_asm, info, operand, &hook->second, state, image_format);
  }

  DCHECK(iter_state == states.end());

  return true;
}

void AsanBasicBlockTransform::set_instrumentation_rate(
    double instrumentation_rate) {
  // Set the instrumentation rate, capping it between 0 and 1.
  instrumentation_rate_ = std::max(0.0, std::min(1.0, instrumentation_rate));
}

bool AsanBasicBlockTransform::TransformBasicBlockSubGraph(
    const TransformPolicyInterface* policy,
    BlockGraph* block_graph,
    BasicBlockSubGraph* subgraph) {
  DCHECK(policy != NULL);
  DCHECK(block_graph != NULL);
  DCHECK(subgraph != NULL);

  // Perform a global liveness analysis.
  if (use_liveness_analysis_)
    liveness_.Analyze(subgraph);

  // Perform a redundant memory access analysis.
  if (remove_redundant_checks_)
    memory_accesses_.Analyze(subgraph);

  // Determines if this subgraph uses unconventional stack pointer
  // manipulations.
  StackAccessMode stack_mode = kUnsafeStackAccess;
  if (!block_graph::HasUnexpectedStackFrameManipulation(subgraph))
    stack_mode = kSafeStackAccess;

  // Iterates through each basic block and instruments it.
  BasicBlockSubGraph::BBCollection::iterator it =
      subgraph->basic_blocks().begin();
  for (; it != subgraph->basic_blocks().end(); ++it) {
    BasicCodeBlock* bb = BasicCodeBlock::Cast(*it);
    if (bb != NULL &&
        !InstrumentBasicBlock(bb, stack_mode, block_graph->image_format())) {
      return false;
    }
  }
  return true;
}

const char AsanTransform::kTransformName[] = "SyzyAsanTransform";

const char AsanTransform::kAsanHookStubName[] = "asan_hook_stub";

const char AsanTransform::kSyzyAsanDll[] = "syzyasan_rtl.dll";

AsanTransform::AsanTransform()
    : asan_dll_name_(kSyzyAsanDll),
      debug_friendly_(false),
      use_liveness_analysis_(false),
      remove_redundant_checks_(false),
      use_interceptors_(false),
      instrumentation_rate_(1.0),
      asan_parameters_(NULL),
      check_access_hooks_ref_(),
      asan_parameters_block_(NULL) {
}

void AsanTransform::set_instrumentation_rate(double instrumentation_rate) {
  // Set the instrumentation rate, capping it between 0 and 1.
  instrumentation_rate_ = std::max(0.0, std::min(1.0, instrumentation_rate));
}

bool AsanTransform::PreBlockGraphIteration(
    const TransformPolicyInterface* policy,
    BlockGraph* block_graph,
    BlockGraph::Block* header_block) {
  DCHECK_NE(reinterpret_cast<TransformPolicyInterface*>(NULL), policy);
  DCHECK_NE(reinterpret_cast<BlockGraph*>(NULL), block_graph);
  DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), header_block);
  DCHECK(block_graph->image_format() == BlockGraph::PE_IMAGE ||
         block_graph->image_format() == BlockGraph::COFF_IMAGE);

  // Ensure that this image has not already been instrumented.
  if (block_graph->FindSection(common::kThunkSectionName)) {
    LOG(ERROR) << "The image is already instrumented.";
    return false;
  }

  AccessHookParamVector access_hook_param_vec;
  AsanBasicBlockTransform::AsanDefaultHookMap default_stub_map;

  // We only need to add stubs for PE images. COFF images use direct references,
  // and the linker takes care of dragging in the appropriate code for us.
  if (block_graph->image_format() == BlockGraph::PE_IMAGE) {
    // Create the hook stub for read/write instructions.
    BlockGraph::Reference read_write_hook;
    if (!CreateHooksStub(block_graph, kAsanHookStubName,
                         AsanBasicBlockTransform::kReadAccess,
                         &read_write_hook)) {
      return false;
    }

    // Create the hook stub for strings instructions.
    BlockGraph::Reference instr_hook;
    if (!CreateHooksStub(block_graph, kAsanHookStubName,
                         AsanBasicBlockTransform::kInstrAccess,
                         &instr_hook)) {
      return false;
    }

    // Map each memory access kind to an appropriate stub.
    default_stub_map[AsanBasicBlockTransform::kReadAccess] = read_write_hook;
    default_stub_map[AsanBasicBlockTransform::kWriteAccess] = read_write_hook;
    default_stub_map[AsanBasicBlockTransform::kInstrAccess] = instr_hook;
    default_stub_map[AsanBasicBlockTransform::kRepzAccess] = instr_hook;
    default_stub_map[AsanBasicBlockTransform::kRepnzAccess] = instr_hook;
  }

  // Add an import entry for the ASAN runtime.
  ImportedModule import_module(asan_dll_name_, kDateInThePast);

  // Import the hooks for the read/write accesses.
  for (int access_size = 1; access_size <= 32; access_size *= 2) {
    MemoryAccessInfo read_info =
        { AsanBasicBlockTransform::kReadAccess, access_size, 0, true };
    access_hook_param_vec.push_back(read_info);
    if (use_liveness_analysis()) {
      read_info.save_flags = false;
      access_hook_param_vec.push_back(read_info);
    }

    MemoryAccessInfo write_info =
        { AsanBasicBlockTransform::kWriteAccess, access_size, 0, true };
    access_hook_param_vec.push_back(write_info);
    if (use_liveness_analysis()) {
      write_info.save_flags = false;
      access_hook_param_vec.push_back(write_info);
    }
  }

  // Import the hooks for the read/write 10-bytes accesses.
  MemoryAccessInfo read_info_10 =
      { AsanBasicBlockTransform::kReadAccess, 10, 0, true };
  access_hook_param_vec.push_back(read_info_10);
  if (use_liveness_analysis()) {
    read_info_10.save_flags = false;
    access_hook_param_vec.push_back(read_info_10);
  }

  MemoryAccessInfo write_info_10 =
      { AsanBasicBlockTransform::kWriteAccess, 10, 0, true };
  access_hook_param_vec.push_back(write_info_10);
  if (use_liveness_analysis()) {
    write_info_10.save_flags = false;
    access_hook_param_vec.push_back(write_info_10);
  }

  // Import the hooks for strings/prefix memory accesses.
  const _InstructionType strings[] = { I_CMPS, I_MOVS, I_STOS };
  int strings_length = sizeof(strings)/sizeof(_InstructionType);

  for (int access_size = 1; access_size <= 4; access_size *= 2) {
    for (int inst = 0; inst < strings_length; ++inst) {
      MemoryAccessInfo repz_inst_info = {
         AsanBasicBlockTransform::kRepzAccess,
         access_size,
         strings[inst],
         true
      };
      access_hook_param_vec.push_back(repz_inst_info);

      MemoryAccessInfo inst_info = {
          AsanBasicBlockTransform::kInstrAccess,
          access_size,
          strings[inst],
          true
      };
      access_hook_param_vec.push_back(inst_info);
    }
  }

  if (!AddAsanCheckAccessHooks(access_hook_param_vec,
                               default_stub_map,
                               &import_module,
                               &check_access_hooks_ref_,
                               policy,
                               block_graph,
                               header_block)) {
    return false;
  }
  return true;
}

bool AsanTransform::OnBlock(const TransformPolicyInterface* policy,
                            BlockGraph* block_graph,
                            BlockGraph::Block* block) {
  DCHECK(policy != NULL);
  DCHECK(block_graph != NULL);
  DCHECK(block != NULL);

  if (!policy->BlockIsSafeToBasicBlockDecompose(block))
    return true;

  // Use the filter that was passed to us for our child transform.
  AsanBasicBlockTransform transform(&check_access_hooks_ref_);
  transform.set_debug_friendly(debug_friendly());
  transform.set_use_liveness_analysis(use_liveness_analysis());
  transform.set_remove_redundant_checks(remove_redundant_checks());
  transform.set_filter(filter());
  transform.set_instrumentation_rate(instrumentation_rate_);

  if (!ApplyBasicBlockSubGraphTransform(
          &transform, policy, block_graph, block, NULL)) {
    return false;
  }

  return true;
}

bool AsanTransform::PostBlockGraphIteration(
    const TransformPolicyInterface* policy,
    BlockGraph* block_graph,
    BlockGraph::Block* header_block) {
  DCHECK(policy != NULL);
  DCHECK(block_graph != NULL);
  DCHECK(header_block != NULL);

  if (block_graph->image_format() == BlockGraph::PE_IMAGE) {
    if (!PeInterceptFunctions(kAsanIntercepts, policy, block_graph,
                              header_block)) {
      return false;
    }

    if (!PeInjectAsanParameters(policy, block_graph, header_block))
      return false;
  } else {
    DCHECK_EQ(BlockGraph::COFF_IMAGE, block_graph->image_format());
    if (!CoffInterceptFunctions(kAsanIntercepts, policy, block_graph,
                                header_block)) {
      return false;
    }
  }

  return true;
}

bool AsanTransform::PeInterceptFunctions(
    const AsanIntercept* intercepts,
    const TransformPolicyInterface* policy,
    BlockGraph* block_graph,
    BlockGraph::Block* header_block) {
  DCHECK_NE(reinterpret_cast<AsanIntercept*>(NULL), intercepts);
  DCHECK_NE(reinterpret_cast<TransformPolicyInterface*>(NULL), policy);
  DCHECK_NE(reinterpret_cast<BlockGraph*>(NULL), block_graph);
  DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), header_block);
  DCHECK_EQ(BlockGraph::PE_IMAGE, block_graph->image_format());

  // This is used to keep track of the index of imports to the ASAN RTL.
  ImportNameIndexMap import_name_index_map;

  // Keeps track of all imported modules with imports that we intercept.
  ScopedVector<ImportedModule> imported_modules;

  ImportedModule asan_rtl(asan_dll_name_, kDateInThePast);

  // Determines what PE imports need to be intercepted, adding them to
  // |asan_rtl| and |import_name_index_map|.
  if (!PeFindImportsToIntercept(use_interceptors_,
                                intercepts,
                                policy,
                                block_graph,
                                header_block,
                                &imported_modules,
                                &import_name_index_map,
                                &asan_rtl)) {
    return false;
  }

  // Keep track of how many import redirections are to be performed. This allows
  // a minor optimization later on when there are none to be performed.
  size_t import_redirection_count = asan_rtl.size();

  // Find statically linked function blocks to intercept, adding them to
  // |asan_rtl| and |import_name_index_map|.
  std::vector<BlockGraph::Block*> static_blocks;
  PeFindStaticallyLinkedFunctionsToIntercept(use_interceptors_,
                                             intercepts,
                                             block_graph,
                                             &static_blocks,
                                             &import_name_index_map,
                                             &asan_rtl);

  // If no imports were found at all, then there are no redirections to perform.
  if (asan_rtl.size() == 0)
    return true;

  // Add the ASAN RTL imports to the image.
  PEAddImportsTransform add_imports_transform;
  add_imports_transform.AddModule(&asan_rtl);
  if (!add_imports_transform.TransformBlockGraph(
          policy, block_graph, header_block)) {
    LOG(ERROR) << "Unable to add imports for redirection.";
    return false;
  }

  // This keeps track of reference redirections that need to be performed.
  pe::ReferenceMap reference_redirect_map;

  if (import_redirection_count > 0) {
    PeGetRedirectsForInterceptedImports(imported_modules,
                                        import_name_index_map,
                                        asan_rtl,
                                        &reference_redirect_map);
  }

  // Adds redirect information for any intercepted statically linked functions.
  if (!static_blocks.empty()) {
    if (!PeGetRedirectsForStaticallyLinkedFunctions(static_blocks,
                                                    import_name_index_map,
                                                    asan_rtl,
                                                    block_graph,
                                                    &reference_redirect_map)) {
      return false;
    }
  }

  // Finally, redirect all references to intercepted functions.
  pe::RedirectReferences(reference_redirect_map);

  return true;
}

bool AsanTransform::PeInjectAsanParameters(
    const TransformPolicyInterface* policy,
    BlockGraph* block_graph,
    BlockGraph::Block* header_block) {
  DCHECK_NE(reinterpret_cast<TransformPolicyInterface*>(NULL), policy);
  DCHECK_NE(reinterpret_cast<BlockGraph*>(NULL), block_graph);
  DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), header_block);
  DCHECK_EQ(BlockGraph::PE_IMAGE, block_graph->image_format());

  // If there are no parameters then do nothing.
  if (asan_parameters_ == NULL)
    return true;

  // Serialize the parameters into a new block.
  common::FlatAsanParameters fparams(*asan_parameters_);
  BlockGraph::Block* params_block = block_graph->AddBlock(
      BlockGraph::DATA_BLOCK, fparams.data().size(), "AsanParameters");
  DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), params_block);
  params_block->CopyData(fparams.data().size(), fparams.data().data());

  // Wire up any references that are required.
  COMPILE_ASSERT(2 == common::kAsanParametersVersion,
                 pointers_in_the_params_must_be_linked_up_here);
  block_graph::TypedBlock<common::AsanParameters> params;
  CHECK(params.Init(0, params_block));
  if (fparams->ignored_stack_ids != NULL) {
    size_t offset = reinterpret_cast<const uint8*>(fparams->ignored_stack_ids) -
        reinterpret_cast<const uint8*>(&fparams.params());
    CHECK(params.SetReference(BlockGraph::ABSOLUTE_REF,
                              params->ignored_stack_ids,
                              params_block,
                              offset,
                              offset));
  }

  // Create an appropriately named section and put the parameters there. The
  // RTL looks for this named section to find the parameters.
  BlockGraph::Section* section = block_graph->FindOrAddSection(
      common::kAsanParametersSectionName,
      common::kAsanParametersSectionCharacteristics);
  DCHECK_NE(reinterpret_cast<BlockGraph::Section*>(NULL), section);
  params_block->set_section(section->id());

  // Remember the block containing the parameters. This is a unittesting seam.
  asan_parameters_block_ = params_block;

  return true;
}

bool AsanTransform::CoffInterceptFunctions(
    const AsanIntercept* intercepts,
    const TransformPolicyInterface* policy,
    BlockGraph* block_graph,
    BlockGraph::Block* header_block) {
  DCHECK_NE(reinterpret_cast<AsanIntercept*>(NULL), intercepts);
  DCHECK_NE(reinterpret_cast<TransformPolicyInterface*>(NULL), policy);
  DCHECK_NE(reinterpret_cast<BlockGraph*>(NULL), block_graph);
  DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL), header_block);

  // Extract the existing symbols.
  pe::CoffSymbolNameOffsetMap symbol_map;
  BlockGraph::Block* symbols_block = NULL;
  BlockGraph::Block* strings_block = NULL;
  if (!pe::FindCoffSpecialBlocks(block_graph, NULL, &symbols_block,
                                 &strings_block)) {
    LOG(ERROR) << "Unable to find COFF header blocks.";
    return false;
  }
  if (!pe::BuildCoffSymbolNameOffsetMap(block_graph, &symbol_map)) {
    LOG(ERROR) << "Unable to build symbol map.";
    return false;
  }

  // Populate a COFF symbol rename transform for each function to be
  // intercepted. We simply try to rename all possible symbols that may exist
  // and allow the transform to ignore any that aren't present.
  pe::transforms::CoffRenameSymbolsTransform rename_tx;
  rename_tx.set_symbols_must_exist(false);
  const AsanIntercept* intercept = intercepts;
  bool defines_asan_functions = false;
  for (; intercept->undecorated_name != NULL; ++intercept) {
    // Skip disabled optional functions.
    if (!use_interceptors_ && intercept->optional)
      continue;

    // Skip functions for which we have no decorated name.
    if (intercept->decorated_name == NULL)
      continue;

    // Build the name of the imported version of this symbol.
    std::string imp_name(kDecoratedImportPrefix);
    imp_name += intercept->decorated_name;

    // Build the name of the ASAN instrumented version of this symbol.
    std::string asan_name(kDecoratedAsanInterceptPrefix);
    asan_name += intercept->decorated_name;

    // Build the name of the ASAN instrumented imported version of this symbol.
    std::string imp_asan_name(kDecoratedImportPrefix);
    imp_asan_name += asan_name;

    // Build symbol rename mappings for the direct and indirect versions of the
    // function.
    rename_tx.AddSymbolMapping(intercept->decorated_name, asan_name);
    rename_tx.AddSymbolMapping(imp_name, imp_asan_name);

    // We use the add imports transform to try to find names for the ASAN
    // implementation. If these already exist in the object file then our
    // instrumentation will fail.
    const std::string* names[] = { &asan_name, &imp_asan_name };
    for (size_t i = 0; i < arraysize(names); ++i) {
      if (symbol_map.count(*names[i])) {
        LOG(ERROR) << "Object file being instrumented defines ASAN function \""
                   << asan_name << "\".";
        defines_asan_functions = true;
      }
    }
  }

  if (defines_asan_functions)
    return false;

  // Apply the rename transform.
  if (!block_graph::ApplyBlockGraphTransform(&rename_tx,
                                             policy,
                                             block_graph,
                                             header_block)) {
    LOG(ERROR) << "Failed to apply COFF symbol rename transform.";
    return false;
  }

  return true;
}

bool operator<(const AsanBasicBlockTransform::MemoryAccessInfo& left,
               const AsanBasicBlockTransform::MemoryAccessInfo& right) {
  if (left.mode != right.mode)
    return left.mode < right.mode;
  if (left.size != right.size)
    return left.size < right.size;
  if (left.save_flags != right.save_flags)
    return left.save_flags < right.save_flags;
  return left.opcode < right.opcode;
}

}  // namespace transforms
}  // namespace instrument

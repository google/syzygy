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

#include "syzygy/pe/old_decomposer.h"

#include <cvconst.h>
#include <algorithm>

#include "base/bind.h"
#include "base/logging.h"
#include "base/path_service.h"
#include "base/string_util.h"
#include "base/stringprintf.h"
#include "base/utf_string_conversions.h"
#include "base/files/file_path.h"
#include "base/memory/scoped_ptr.h"
#include "base/win/scoped_bstr.h"
#include "base/win/scoped_comptr.h"
#include "sawbuck/common/com_utils.h"
#include "sawbuck/sym_util/types.h"
#include "syzygy/block_graph/block_util.h"
#include "syzygy/block_graph/typed_block.h"
#include "syzygy/core/disassembler_util.h"
#include "syzygy/core/zstream.h"
#include "syzygy/pdb/omap.h"
#include "syzygy/pdb/pdb_byte_stream.h"
#include "syzygy/pdb/pdb_util.h"
#include "syzygy/pe/dia_util.h"
#include "syzygy/pe/find.h"
#include "syzygy/pe/metadata.h"
#include "syzygy/pe/pdb_info.h"
#include "syzygy/pe/pe_file_parser.h"
#include "syzygy/pe/pe_transform_policy.h"
#include "syzygy/pe/pe_utils.h"
#include "syzygy/pe/serialization.h"

namespace pe {
namespace {

using base::win::ScopedBstr;
using base::win::ScopedComPtr;
using block_graph::BlockGraph;
using block_graph::ConstTypedBlock;
using builder::Opt;
using builder::Seq;
using builder::Star;
using core::AbsoluteAddress;
using core::Disassembler;
using core::RelativeAddress;

typedef Disassembler::CallbackDirective CallbackDirective;

const size_t kPointerSize = sizeof(AbsoluteAddress);

// Converts from PdbFixup::Type to BlockGraph::ReferenceType.
BlockGraph::ReferenceType PdbFixupTypeToReferenceType(
    pdb::PdbFixup::Type type) {
  switch (type) {
    case pdb::PdbFixup::TYPE_ABSOLUTE:
      return BlockGraph::ABSOLUTE_REF;

    case pdb::PdbFixup::TYPE_RELATIVE:
      return BlockGraph::RELATIVE_REF;

    case pdb::PdbFixup::TYPE_PC_RELATIVE:
      return BlockGraph::PC_RELATIVE_REF;

    default:
      NOTREACHED() << "Invalid PdbFixup::Type.";
      // The return type here is meaningless.
      return BlockGraph::ABSOLUTE_REF;
  }
}

// Adds a reference to the provided intermediate reference map. If one already
// exists, will validate that they are consistent.
bool AddReference(RelativeAddress src_addr,
                  BlockGraph::ReferenceType type,
                  BlockGraph::Size size,
                  RelativeAddress dst_base,
                  BlockGraph::Offset dst_offset,
                  OldDecomposer::IntermediateReferenceMap* references) {
  DCHECK(references != NULL);

  // If we get an iterator to a reference and it has the same source address
  // then ensure that we are consistent with it.
  OldDecomposer::IntermediateReferenceMap::iterator it =
      references->lower_bound(src_addr);
  if (it != references->end() && it->first == src_addr) {
    if (type != it->second.type || size != it->second.size ||
        dst_base != it->second.base || dst_offset != it->second.offset) {
      LOG(ERROR) << "Trying to insert inconsistent and colliding intermediate "
                    "references.";
      return false;
    }
  }

  OldDecomposer::IntermediateReference ref = { type,
                                            size,
                                            dst_base,
                                            dst_offset };

  // Since we used lower_bound above, we can use it as a hint for the
  // insertion. This saves us from incurring the lookup cost twice.
  references->insert(it, std::make_pair(src_addr, ref));
  return true;
}

// Validates the given reference against the given fixup map entry. If they
// are consistent, marks the fixup as having been visited.
bool ValidateReference(RelativeAddress src_addr,
                       BlockGraph::ReferenceType type,
                       BlockGraph::Size size,
                       OldDecomposer::FixupMap::iterator fixup_it) {
  if (type != fixup_it->second.type || size != kPointerSize) {
    LOG(ERROR) << "Reference at " << src_addr
               << " not consistent with corresponding fixup.";
    return false;
  }

  // Mark this fixup as having been visited.
  fixup_it->second.visited = true;

  return true;
}

enum ValidateOrAddReferenceMode {
  // Look for an existing fixup. If we find one, validate against it,
  // otherwise create a new intermediate reference.
  FIXUP_MAY_EXIST,
  // Compare against an existing fixup, bailing if there is none. Does not
  // create a new intermediate reference.
  FIXUP_MUST_EXIST,
  // Look for an existing fixup, and fail if one exists. Otherwise, create
  // a new intermediate reference.
  FIXUP_MUST_NOT_EXIST
};
bool ValidateOrAddReference(
    ValidateOrAddReferenceMode mode,
    RelativeAddress src_addr,
    BlockGraph::ReferenceType type,
    BlockGraph::Size size,
    RelativeAddress dst_base,
    BlockGraph::Offset dst_offset,
    OldDecomposer::FixupMap* fixup_map,
    OldDecomposer::IntermediateReferenceMap* references) {
  DCHECK(fixup_map != NULL);
  DCHECK(references != NULL);

  OldDecomposer::FixupMap::iterator it = fixup_map->find(src_addr);

  switch (mode) {
    case FIXUP_MAY_EXIST: {
      if (it != fixup_map->end() &&
          !ValidateReference(src_addr, type, size, it))
        return false;
      return AddReference(src_addr, type, size, dst_base, dst_offset,
                          references);
    }

    case FIXUP_MUST_EXIST: {
      if (it == fixup_map->end()) {
        LOG(ERROR) << "Reference at " << src_addr << " has no matching fixup.";
        return false;
      }
      if (!ValidateReference(src_addr, type, size, it))
        return false;
      // Do not create a new intermediate reference.
      return true;
    }

    case FIXUP_MUST_NOT_EXIST: {
      if (it != fixup_map->end()) {
        LOG(ERROR) << "Reference at " << src_addr
                   << " collides with an existing fixup.";
        return false;
      }
      return AddReference(src_addr, type, size, dst_base, dst_offset,
                          references);
    }

    default: {
      NOTREACHED() << "Invalid ValidateOrAddReferenceMode.";
      return false;
    }
  }
}

bool GetTypeInfo(IDiaSymbol* symbol, size_t* length) {
  DCHECK(symbol != NULL);
  DCHECK(length != NULL);

  *length = 0;
  ScopedComPtr<IDiaSymbol> type;
  HRESULT hr = symbol->get_type(type.Receive());
  // This happens if the symbol has no type information.
  if (hr == S_FALSE)
    return true;
  if (hr != S_OK) {
    LOG(ERROR) << "Failed to get type symbol: " << com::LogHr(hr) << ".";
    return false;
  }

  ULONGLONG ull_length = 0;
  hr = type->get_length(&ull_length);
  if (hr != S_OK) {
    LOG(ERROR) << "Failed to retrieve type length properties: "
               << com::LogHr(hr) << ".";
    return false;
  }
  *length = ull_length;

  return true;
}

SectionType GetSectionType(const IMAGE_SECTION_HEADER* header) {
  DCHECK(header != NULL);
  if ((header->Characteristics & IMAGE_SCN_CNT_CODE) != 0)
    return kSectionCode;
  if ((header->Characteristics & kReadOnlyDataCharacteristics) != 0)
    return kSectionData;
  return kSectionUnknown;
}

void GuessDataBlockAlignment(BlockGraph::Block* block, uint32 max_alignment) {
  DCHECK(block != NULL);
  uint32 alignment = block->addr().GetAlignment();
  // Cap the alignment.
  if (alignment > max_alignment)
    alignment = max_alignment;
  block->set_alignment(alignment);
}

bool AreMatchedBlockAndLabelAttributes(
    BlockGraph::BlockType bt,
    BlockGraph::LabelAttributes la) {
  return (bt == BlockGraph::CODE_BLOCK && (la & BlockGraph::CODE_LABEL) != 0) ||
      (bt == BlockGraph::DATA_BLOCK && (la & BlockGraph::DATA_LABEL) != 0);
}

BlockGraph::LabelAttributes SymTagToLabelAttributes(enum SymTagEnum sym_tag) {
  switch (sym_tag) {
    case SymTagData:
      return BlockGraph::DATA_LABEL;
    case SymTagLabel:
      return BlockGraph::CODE_LABEL;
    case SymTagFuncDebugStart:
      return BlockGraph::DEBUG_START_LABEL;
    case SymTagFuncDebugEnd:
      return BlockGraph::DEBUG_END_LABEL;
    case SymTagBlock:
      return BlockGraph::SCOPE_START_LABEL;
    case SymTagCallSite:
      return BlockGraph::CALL_SITE_LABEL;
  }

  NOTREACHED();
  return 0;
}

bool AddLabelToBlock(RelativeAddress addr,
                     const base::StringPiece& name,
                     BlockGraph::LabelAttributes label_attributes,
                     BlockGraph::Block* block) {
  DCHECK(block != NULL);
  DCHECK_LE(block->addr(), addr);
  DCHECK_GT(block->addr() + block->size(), addr);

  BlockGraph::Offset offset = addr - block->addr();

  // Try to create the label.
  if (block->SetLabel(offset, name, label_attributes)) {
    // If there was no label at offset 0, then this block has not yet been
    // renamed, and still has its section contribution as a name. Update it to
    // the first symbol we get for it. We parse symbols from most useful
    // (undecorated function names) to least useful (mangled public symbols), so
    // this ensures a block has the most useful name.
    if (offset == 0)
      block->set_name(name);

    return true;
  }

  // If we get here there's an already existing label. Update it.
  BlockGraph::Label label;
  CHECK(block->GetLabel(offset, &label));

  // It is conceivable that there could be more than one scope with either the
  // same beginning or the same ending. However, this doesn't appear to happen
  // in any version of Chrome up to 20. We add this check so that we'd at least
  // be made aware of the situation. (We don't rely on these labels, so we
  // merely output a warning rather than an error.)
  {
    const BlockGraph::LabelAttributes kScopeAttributes =
        BlockGraph::SCOPE_START_LABEL |
        BlockGraph::SCOPE_END_LABEL;
    BlockGraph::LabelAttributes scope_attributes =
        label_attributes & kScopeAttributes;
    if (scope_attributes != 0) {
      if (label.has_any_attributes(scope_attributes)) {
        LOG(WARNING) << "Detected colliding scope labels at offset "
                     << offset << " of block \"" << block->name() << "\".";
      }
    }
  }

  // Merge the names if this isn't a repeated name.
  std::string new_name = label.name();
  if (new_name.find(name.data()) == new_name.npos) {
    new_name.append(", ");
    name.AppendToString(&new_name);
  }

  // Merge the attributes.
  BlockGraph::LabelAttributes new_label_attr = label.attributes() |
      label_attributes;
  if (!BlockGraph::Label::AreValidAttributes(new_label_attr)) {
    // It's not clear which attributes should be the winner here, so we log an
    // error.
    LOG(ERROR) << "Trying to merge conflicting label attributes \""
               << BlockGraph::LabelAttributesToString(label_attributes)
               << "\" for label \"" << label.ToString() << "\" at offset "
               << offset << " of block \"" << block->name() << "\".";
    return false;
  }

  // Update the label.
  label = BlockGraph::Label(new_name, new_label_attr);
  CHECK(block->RemoveLabel(offset));
  CHECK(block->SetLabel(offset, label));

  return true;
}

// The MS linker pads between code blocks with int3s.
static const uint8 kInt3 = 0xCC;

// If the given run of bytes consists of a single value repeated, returns that
// value. Otherwise, returns -1.
int RepeatedValue(const uint8* data, size_t size) {
  DCHECK(data != NULL);
  const uint8* data_end = data + size;
  uint8 value = *(data++);
  for (; data < data_end; ++data) {
    if (*data != value)
      return -1;
  }
  return value;
}

const BlockGraph::BlockId kNullBlockId(-1);

void GetDisassemblyStartingPoints(
    const BlockGraph::Block* block,
    AbsoluteAddress abs_block_addr,
    const PEFile::RelocSet& reloc_set,
    Disassembler::AddressSet* addresses) {
  DCHECK(block != NULL);
  DCHECK_EQ(BlockGraph::CODE_BLOCK, block->type());
  DCHECK(addresses != NULL);

  addresses->clear();

  // Use code labels as starting points.
  BlockGraph::Block::LabelMap::const_iterator it(block->labels().begin());
  for (; it != block->labels().end(); ++it) {
    BlockGraph::Offset offset = it->first;
    DCHECK_LE(0, offset);
    DCHECK_GT(block->size(), static_cast<size_t>(offset));

    if (it->second.has_attributes(BlockGraph::CODE_LABEL)) {
      // We sometimes receive code labels that land on lookup tables; we can
      // detect these because the label will point directly to a reloc. These
      // should have already been marked as data by now. DCHECK to validate.
      // TODO(chrisha): Get rid of this DCHECK, and allow mixed CODE and DATA
      //     labels. Simply only use ones that are DATA only.
      DCHECK_EQ(0u, reloc_set.count(block->addr() + offset));

      addresses->insert(abs_block_addr + offset);
    }
  }
}

// Determines if the provided code block has the expected layout of code first,
// data second. Returns true if so, false otherwise. Also returns the size of
// the code portion of the block by trimming off any data labels.
bool BlockHasExpectedCodeDataLayout(const BlockGraph::Block* block,
                                    size_t* code_size) {
  DCHECK(block != NULL);
  DCHECK_EQ(BlockGraph::CODE_BLOCK, block->type());
  DCHECK(code_size != NULL);

  *code_size = block->data_size();

  BlockGraph::Block::LabelMap::const_reverse_iterator label_it =
      block->labels().rbegin();
  BlockGraph::Block::LabelMap::const_reverse_iterator label_end =
      block->labels().rend();

  bool seen_non_data = false;

  // Walk through the labels in reverse order (by decreasing offset). Trim
  // any data labels from this blocks data_size.
  for (; label_it != label_end; ++label_it) {
    if (label_it->second.has_attributes(BlockGraph::DATA_LABEL)) {
      // We've encountered data not strictly at the end of the block. This
      // violates assumptions about code generated by cl.exe.
      if (seen_non_data)
        return false;

      // Otherwise, we're still in a run of data labels at the tail of the
      // block. Keep trimming the code size.
      size_t offset = static_cast<size_t>(label_it->first);
      if (offset < *code_size)
        *code_size = offset;
    } else {
      seen_non_data = true;
    }
  }

  return true;
}

// Given a compiland, returns its compiland details.
bool GetCompilandDetailsForCompiland(IDiaSymbol* compiland,
                                     IDiaSymbol** compiland_details) {
  DCHECK(compiland != NULL);
  DCHECK(compiland_details != NULL);
  DCHECK(IsSymTag(compiland, SymTagCompiland));

  *compiland_details = NULL;

  // Get the enumeration of compiland details.
  ScopedComPtr<IDiaEnumSymbols> enum_symbols;
  HRESULT hr = compiland->findChildren(SymTagCompilandDetails, NULL, 0,
                                       enum_symbols.Receive());
  DCHECK_EQ(S_OK, hr);

  // We expect there to be compiland details. For compilands built by
  // non-standard toolchains, there usually aren't any.
  LONG count = 0;
  hr = enum_symbols->get_Count(&count);
  DCHECK_EQ(S_OK, hr);
  if (count == 0)
    return false;

  // Get the compiland details.
  ULONG fetched = 0;
  hr = enum_symbols->Next(1, compiland_details, &fetched);
  DCHECK_EQ(S_OK, hr);
  DCHECK_EQ(1u, fetched);
  return true;
}

// Stores information regarding known compilers.
struct KnownCompilerInfo {
  wchar_t* compiler_name;
  bool supported;
};

// A list of known compilers, and their status as being supported or not.
KnownCompilerInfo kKnownCompilerInfos[] = {
  { L"Microsoft (R) Macro Assembler", false },
  { L"Microsoft (R) Optimizing Compiler", true },
  { L"Microsoft (R) LINK", false }
};

// Given a compiland, determines whether the compiler used is one of those that
// we whitelist.
bool IsBuiltBySupportedCompiler(IDiaSymbol* compiland) {
  DCHECK(compiland != NULL);
  DCHECK(IsSymTag(compiland, SymTagCompiland));

  ScopedComPtr<IDiaSymbol> compiland_details;
  if (!GetCompilandDetailsForCompiland(compiland,
                                       compiland_details.Receive())) {
    // If the compiland has no compiland details we assume the compiler is not
    // supported.
    ScopedBstr compiland_name;
    if (compiland->get_name(compiland_name.Receive()) == S_OK) {
      VLOG(1) << "Compiland has no compiland details: "
              << com::ToString(compiland_name);
    }
    return false;
  }
  DCHECK(compiland_details.get() != NULL);

  // Get the compiler name.
  ScopedBstr compiler_name;
  HRESULT hr = compiland_details->get_compilerName(compiler_name.Receive());
  DCHECK_EQ(S_OK, hr);

  // Check the compiler name against the list of known compilers.
  for (size_t i = 0; i < arraysize(kKnownCompilerInfos); ++i) {
    if (::wcscmp(kKnownCompilerInfos[i].compiler_name, compiler_name) == 0) {
      return kKnownCompilerInfos[i].supported;
    }
  }

  // Anything we don't explicitly know about is not supported.
  VLOG(1) << "Encountered unknown compiler: " << compiler_name;
  return false;
}

// Logs an error if @p error is true, a verbose logging message otherwise.
#define LOG_ERROR_OR_VLOG1(error) LAZY_STREAM( \
    ::logging::LogMessage(__FILE__, \
                          __LINE__, \
                          (error) ? ::logging::LOG_ERROR : -1).stream(), \
    (error ? LOG_IS_ON(ERROR) : VLOG_IS_ON(1)))

// Logs a warning if @p warn is true, a verbose logging message otherwise.
#define LOG_WARNING_OR_VLOG1(warn) LAZY_STREAM( \
    ::logging::LogMessage(__FILE__, \
                          __LINE__, \
                          (warn) ? ::logging::LOG_WARNING : -1).stream(), \
    (warn ? LOG_IS_ON(WARNING) : VLOG_IS_ON(1)))

// Sets the disassembler directive to an error if @p strict is true, otherwise
// sets it to an early termination.
CallbackDirective AbortOrTerminateDisassembly(bool strict) {
  if (strict)
    return Disassembler::kDirectiveAbort;
  else
    return Disassembler::kDirectiveTerminateWalk;
}

// Returns true if the callback-directive is an early termination that should be
// returned immediately.
bool IsFatalCallbackDirective(CallbackDirective directive) {
  switch (directive) {
    case Disassembler::kDirectiveContinue:
    case Disassembler::kDirectiveTerminatePath:
      return false;

    case Disassembler::kDirectiveTerminateWalk:
    case Disassembler::kDirectiveAbort:
      return true;

    default:
      NOTREACHED();
  }

  return true;
}

// Combines two callback directives. Higher codes supersede lower ones.
CallbackDirective CombineCallbackDirectives(CallbackDirective d1,
                                            CallbackDirective d2) {
  // This ensures that this logic remains valid. This should prevent people
  // from tinkering with CallbackDirective and breaking this code.
  COMPILE_ASSERT(Disassembler::kDirectiveContinue <
                     Disassembler::kDirectiveTerminatePath &&
                 Disassembler::kDirectiveTerminatePath <
                     Disassembler::kDirectiveTerminateWalk &&
                 Disassembler::kDirectiveTerminateWalk <
                     Disassembler::kDirectiveAbort,
                 callback_directive_enum_is_not_sorted);
  return std::max(d1, d2);
}

// Determines if the given block has a data label in the given range of bytes.
bool HasDataLabelInRange(const BlockGraph::Block* block,
                         BlockGraph::Offset offset,
                         BlockGraph::Size size) {
  BlockGraph::Block::LabelMap::const_iterator it =
      block->labels().lower_bound(offset);
  BlockGraph::Block::LabelMap::const_iterator end =
      block->labels().lower_bound(offset + size);

  for (; it != end; ++it) {
    if (it->second.has_attributes(BlockGraph::DATA_LABEL))
      return true;
  }

  return false;
}

void ReportPotentialNonReturningFunction(
    const OldDecomposer::IntermediateReferenceMap& refs,
    const BlockGraph::AddressSpace& image,
    const BlockGraph::Block* block,
    BlockGraph::Offset call_ref_offset,
    const char* reason) {
  typedef OldDecomposer::IntermediateReferenceMap::const_iterator RefIter;

  // Try and track down the block being pointed at by the call. If this is a
  // computed address there will be no reference.
  RefIter ref_it = refs.find(block->addr() + call_ref_offset);
  if (ref_it == refs.end()) {
    LOG(WARNING) << "Suspected non-returning function call from offset "
                 << call_ref_offset << " (followed by " << reason
                 << ") of block \"" << block->name()
                 << "\", but target can not be tracked down.";
    return;
  }

  BlockGraph::Block* target = image.GetBlockByAddress(ref_it->second.base);
  DCHECK(target != NULL);

  // If this was marked as non-returning, then its not suspicious.
  if ((target->attributes() & BlockGraph::NON_RETURN_FUNCTION) != 0)
    return;

  // If the target is a code block then this is a direct call.
  if (target->type() == BlockGraph::CODE_BLOCK) {
    LOG(WARNING) << "Suspected non-returning call from offset "
                 << call_ref_offset << " (followed by " << reason
                 << ") of block \"" << block->name() << "\" to code block \""
                 << target->name() << "\".";
    return;
  }
  // Otherwise the target is a data block and this is a memory indirect call
  // to a thunk.
  DCHECK_EQ(BlockGraph::DATA_BLOCK, target->type());

  // Track down the import thunk.
  RefIter thunk_ref_it = refs.find(ref_it->second.base);
  DCHECK(thunk_ref_it != refs.end());
  BlockGraph::Block* thunk = image.GetBlockByAddress(thunk_ref_it->second.base);

  // If this was marked as non-returning, then its not suspicious.
  if ((thunk->attributes() & BlockGraph::NON_RETURN_FUNCTION) != 0)
    return;

  // Otherwise, this is an import thunk. Get the module and symbol names.
  LOG(WARNING) << "Suspected non-returning call from offset "
               << call_ref_offset << " (followed by " << reason
               << ") of block \"" << block->name() << "\" to import thunk \""
               << thunk->name() << "\".";
}

void LookForNonReturningFunctions(
    const OldDecomposer::IntermediateReferenceMap& refs,
    const BlockGraph::AddressSpace& image,
    const BlockGraph::Block* block,
    const Disassembler& disasm) {
  bool saw_call = false;
  bool saw_call_then_nop = false;
  BlockGraph::Offset call_ref_offset = 0;

  AbsoluteAddress end_of_last_inst;
  Disassembler::VisitedSpace::const_iterator inst_it =
      disasm.visited().begin();
  for (; inst_it != disasm.visited().end(); ++inst_it) {
    // Not contiguous with the last instruction? Then we're spanning a gap. If
    // it's an instruction then we didn't parse it; thus, we already know that
    // if the last instruction is a call it's to a non-returning function. So,
    // we only need to check for data.
    if (inst_it->first.start() != end_of_last_inst) {
      if (saw_call || saw_call_then_nop) {
        BlockGraph::Offset offset = end_of_last_inst - disasm.code_addr();
        BlockGraph::Size size = inst_it->first.start() - end_of_last_inst;
        if (HasDataLabelInRange(block, offset, size))
          // We do not expect this to ever occur in cl.exe generated code.
          // However, it is entirely possible in hand-written assembly.
          ReportPotentialNonReturningFunction(
              refs, image, block, call_ref_offset,
              saw_call ? "data" : "nop(s) and data");
      }

      saw_call = false;
      saw_call_then_nop = false;
    }

    _DInst inst = { 0 };
    BlockGraph::Offset offset = inst_it->first.start() - disasm.code_addr();
    const uint8* code = disasm.code() + offset;
    CHECK(core::DecodeOneInstruction(code, inst_it->first.size(), &inst));

    // Previous instruction was a call?
    if (saw_call) {
      if (core::IsNop(inst)) {
        saw_call_then_nop = true;
      } else if (core::IsDebugInterrupt(inst)) {
        ReportPotentialNonReturningFunction(
            refs, image, block, call_ref_offset, "int3");
      }
      saw_call = false;
    } else if (saw_call_then_nop) {
      // The previous instructions we've seen have been a call followed by
      // arbitrary many nops. Look for another nop to continue the pattern.
      saw_call_then_nop = core::IsNop(inst);
    } else {
      // The previous instruction was not a call, so we're looking for one.
      // If this instruction is a call, remember that fact and also remember
      // the offset of its operand (the call target).
      if (core::IsCall(inst)) {
        saw_call = true;
        call_ref_offset = offset + inst_it->first.size() -
            BlockGraph::Reference::kMaximumSize;
      }
    }

    // Remember the end of the last instruction we processed.
    end_of_last_inst = inst_it->first.end();
  }

  // If the last instruction was a call and we've marked that we've disassembled
  // past the end, then this is also a suspected non-returning function.
  if ((saw_call || saw_call_then_nop) &&
      (block->attributes() & BlockGraph::DISASSEMBLED_PAST_END) != 0) {
    const char* reason = saw_call ? "end of block" : "nop(s) and end of block";
    ReportPotentialNonReturningFunction(
        refs, image, block, call_ref_offset, reason);
  }
}

bool CodeBlockHasAlignedJumpTables(const BlockGraph::Block* block) {
  DCHECK(block != NULL);
  DCHECK_EQ(BlockGraph::CODE_BLOCK, block->type());

  // Iterate over the labels of this block looking for jump tables.
  bool has_jump_tables = false;
  BlockGraph::Block::LabelMap::const_iterator label_it =
      block->labels().begin();
  for (; label_it != block->labels().end(); ++label_it) {
    if (!label_it->second.has_attributes(BlockGraph::JUMP_TABLE_LABEL))
      continue;

    has_jump_tables = true;

    // If the jump table is misaligned we can return false immediately.
    if (label_it->first % kPointerSize != 0)
      return false;
  }

  return has_jump_tables;
}

bool AlignCodeBlocksWithJumpTables(ImageLayout* image_layout) {
  DCHECK(image_layout != NULL);

  BlockGraph::AddressSpace::RangeMapConstIter block_it =
      image_layout->blocks.begin();
  for (; block_it != image_layout->blocks.end(); ++block_it) {
    BlockGraph::Block* block = block_it->second;

    // We only care about code blocks that are already aligned 0 mod 4 but
    // whose explicit alignment is currently less than that.
    if (block->type() != BlockGraph::CODE_BLOCK)
      continue;
    if (block->alignment() >= kPointerSize)
      continue;
    if (block_it->first.start().value() % kPointerSize != 0)
      continue;

    // Inspect them to see if they have aligned jump tables. If they do,
    // set the alignment of the block itself.
    if (CodeBlockHasAlignedJumpTables(block_it->second))
      block->set_alignment(kPointerSize);
  }

  return true;
}

}  // namespace

OldDecomposer::OldDecomposer(const PEFile& image_file)
    : image_(NULL),
      image_file_(image_file),
      current_block_(NULL),
      be_strict_with_current_block_(true) {
  // Register static initializer patterns that we know are always present.
  // CRT C/C++/etc initializers.
  CHECK(RegisterStaticInitializerPatterns("(__x.*)_a", "(__x.*)_z"));
  // RTC (run-time checks) initializers (part of CRT).
  CHECK(RegisterStaticInitializerPatterns("(__rtc_[it])aa", "(__rtc_[it])zz"));
  // ATL object map initializers.
  CHECK(RegisterStaticInitializerPatterns("(__pobjMapEntry)First",
                                          "(__pobjMapEntry)Last"));
  // Thread-local storage template.
  CHECK(RegisterStaticInitializerPatterns("(_tls_)start", "(_tls_)end"));

  // Register non-returning functions that for some reason the symbols lie to
  // us about.
  CHECK(RegisterNonReturningFunction("_CxxThrowException"));
  CHECK(RegisterNonReturningFunction("_longjmp"));

  // Register non-returning imports that we know about.
  CHECK(RegisterNonReturningImport("KERNEL32.dll", "ExitProcess"));
  CHECK(RegisterNonReturningImport("KERNEL32.dll", "ExitThread"));
}

bool OldDecomposer::Decompose(ImageLayout* image_layout) {
  DCHECK_NE(reinterpret_cast<ImageLayout*>(NULL), image_layout);

  // Set the image format.
  image_layout->blocks.graph()->set_image_format(BlockGraph::PE_IMAGE);

  // We start by finding the PDB path.
  if (!FindAndValidatePdbPath())
    return false;
  DCHECK(!pdb_path_.empty());

  // Check if the block-graph has already been serialized into the PDB and load
  // it from here in this case. This allows round-trip decomposition.
  bool stream_exists = false;
  if (LoadBlockGraphFromPdb(pdb_path_, image_file_, image_layout,
                            &stream_exists)) {
    return true;
  } else {
    // If the stream exists but hasn't been loaded we return an error. At this
    // point an error message has already been logged if there was one.
    if (stream_exists)
      return false;
  }

  // Move on to instantiating and initializing our Debug Interface Access
  // session.
  ScopedComPtr<IDiaDataSource> dia_source;
  if (!CreateDiaSource(dia_source.Receive()))
    return false;

  // We create the session using the PDB file directly, as we've already
  // validated that it matches the module.
  ScopedComPtr<IDiaSession> dia_session;
  if (!CreateDiaSession(pdb_path_,
                        dia_source.get(),
                        dia_session.Receive())) {
    return false;
  }

  HRESULT hr = dia_session->put_loadAddress(
      image_file_.nt_headers()->OptionalHeader.ImageBase);
  if (hr != S_OK) {
    LOG(ERROR) << "Failed to set the DIA load address: "
               << com::LogHr(hr) << ".";
    return false;
  }

  ScopedComPtr<IDiaSymbol> global;
  hr = dia_session->get_globalScope(global.Receive());
  if (hr != S_OK) {
    LOG(ERROR) << "Failed to get the DIA global scope: "
               << com::LogHr(hr) << ".";
    return false;
  }

  image_ = &image_layout->blocks;

  // Create the sections for the image.
  bool success = CreateSections();

  // Load FIXUP information from the PDB file. We do this early on so that we
  // can do accounting with references that are created later on.
  if (success)
    success = LoadDebugStreams(dia_session);

  // Create intermediate references for each fixup entry.
  if (success)
    success = CreateReferencesFromFixups();

  // Chunk out important PE image structures, like the headers and such.
  PEFileParser::PEHeader header;
  if (success)
    success = CreatePEImageBlocksAndReferences(&header);

  // Parse and validate the relocation entries.
  if (success)
    success = ParseRelocs();

  // Our first round of parsing is using section contributions. This creates
  // both code and data blocks.
  if (success)
    success = CreateBlocksFromSectionContribs(dia_session);

  // Process the function and thunk symbols in the image. This does not create
  // any blocks, as all functions are covered by section contributions.
  if (success)
    success = ProcessCodeSymbols(global);

  // Process data symbols. This can cause the creation of some blocks as the
  // data sections are not fully covered by section contributions.
  if (success)
    success = ProcessDataSymbols(global);

  // Create labels in code blocks.
  if (success)
    success = CreateGlobalLabels(global);

  // Create gap blocks. This ensures that we have complete coverage of the
  // entire image.
  if (success)
    success = CreateGapBlocks();

  // Parse public symbols, augmenting code and data labels where possible.
  // Some public symbols land on gap blocks, so they need to have been parsed
  // already.
  if (success)
    success = ProcessPublicSymbols(global);

  // Parse initialization bracketing symbols. This needs to happen after
  // PublicSymbols have been parsed.
  if (success)
    success = ProcessStaticInitializers();

  // We know that some data blocks need to have alignment precisely preserved.
  // For now, we very conservatively (guaranteed to be correct, but causes many
  // blocks to be aligned that don't strictly need alignment) guess alignment
  // for each block. This must be run after static initializers have been
  // parsed.
  if (success)
    success = GuessDataBlockAlignments();

  // Disassemble code blocks and create PC-relative references
  if (success)
    success = CreateCodeReferences();

  // Turn the address->address format references we've created into
  // block->block references on the blocks in the image.
  if (success)
    success = FinalizeIntermediateReferences();

  // Everything called after this points requires the references to have been
  // finalized.

  // One way of ensuring full coverage is to check that all of the fixups
  // were visited during decomposition.
  if (success)
    success = ConfirmFixupsVisited();

  // Now, find and label any padding blocks.
  if (success)
    success = FindPaddingBlocks();

  // Copy the image headers over to the layout.
  if (success)
    success = CopyHeaderToImageLayout(header.nt_headers, image_layout);

  // Set the alignment on code blocks with jump tables. This ensures that the
  // jump tables remain aligned post-transform.
  if (success)
    success = AlignCodeBlocksWithJumpTables(image_layout);

  image_ = NULL;

  return success;
}

bool OldDecomposer::FindAndValidatePdbPath() {
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

  // Get the PDB info from the PDB file.
  pdb::PdbInfoHeader70 pdb_info_header;
  if (!pdb::ReadPdbHeader(pdb_path_, &pdb_info_header)) {
    LOG(ERROR) << "Unable to read PDB info header from PDB file: "
               << pdb_path_.value();
    return false;
  }

  // Get the PDB info from the module.
  PdbInfo pdb_info;
  if (!pdb_info.Init(image_file_)) {
    LOG(ERROR) << "Unable to read PDB info from PE file: "
               << image_file_.path().value();
    return false;
  }

  // Ensure that they are consistent.
  if (!pdb_info.IsConsistent(pdb_info_header)) {
    LOG(ERROR) << "PDB file \"" << pdb_path_.value() << "\" does not match "
               << "module \"" << image_file_.path().value() << "\".";
    return false;
  }

  return true;
}

bool OldDecomposer::ProcessCodeSymbols(IDiaSymbol* global) {
  if (!ProcessFunctionSymbols(global))
    return false;
  if (!ProcessThunkSymbols(global))
    return false;

  return true;
}

bool OldDecomposer::ProcessFunctionSymbols(IDiaSymbol* global) {
  DCHECK(IsSymTag(global, SymTagExe));

  // Otherwise enumerate its offspring.
  ScopedComPtr<IDiaEnumSymbols> dia_enum_symbols;
  HRESULT hr = global->findChildren(SymTagFunction,
                                    NULL,
                                    nsNone,
                                    dia_enum_symbols.Receive());
  if (hr != S_OK) {
    LOG(ERROR) << "Failed to get the DIA function enumerator: "
               << com::LogHr(hr) << ".";
    return false;
  }

  LONG count = 0;
  if (dia_enum_symbols->get_Count(&count) != S_OK) {
    LOG(ERROR) << "Failed to get function enumeration length.";
    return false;
  }

  for (LONG visited = 0; visited < count; ++visited) {
    ScopedComPtr<IDiaSymbol> function;
    ULONG fetched = 0;
    hr = dia_enum_symbols->Next(1, function.Receive(), &fetched);
    if (hr != S_OK) {
      LOG(ERROR) << "Failed to enumerate functions: " << com::LogHr(hr) << ".";
      return false;
    }
    if (fetched == 0)
      break;

    // Create the block representing the function.
    DCHECK(IsSymTag(function, SymTagFunction));
    if (!ProcessFunctionOrThunkSymbol(function))
      return false;
  }

  return true;
}

bool OldDecomposer::ProcessFunctionOrThunkSymbol(IDiaSymbol* function) {
  DCHECK(IsSymTag(function, SymTagFunction) || IsSymTag(function, SymTagThunk));

  DWORD location_type = LocIsNull;
  HRESULT hr = E_FAIL;
  if (FAILED(hr = function->get_locationType(&location_type))) {
    LOG(ERROR) << "Failed to retrieve function address type: "
               << com::LogHr(hr) << ".";
    return false;
  }
  if (location_type != LocIsStatic) {
    DCHECK_EQ(static_cast<DWORD>(LocIsNull), location_type);
    return true;
  }

  DWORD rva = 0;
  ULONGLONG length = 0;
  ScopedBstr name;
  if ((hr = function->get_relativeVirtualAddress(&rva)) != S_OK ||
      (hr = function->get_length(&length)) != S_OK ||
      (hr = function->get_name(name.Receive())) != S_OK) {
    LOG(ERROR) << "Failed to retrieve function information: "
               << com::LogHr(hr) << ".";
    return false;
  }

  // Certain properties are not defined on all blocks, so the following calls
  // may return S_FALSE.
  BOOL no_return = FALSE;
  if (function->get_noReturn(&no_return) != S_OK)
    no_return = FALSE;

  BOOL has_inl_asm = FALSE;
  if (function->get_hasInlAsm(&has_inl_asm) != S_OK)
    has_inl_asm = FALSE;

  BOOL has_eh = FALSE;
  if (function->get_hasEH(&has_eh) != S_OK)
    has_eh = FALSE;

  BOOL has_seh = FALSE;
  if (function->get_hasSEH(&has_seh) != S_OK)
    has_seh = FALSE;

  std::string block_name;
  if (!WideToUTF8(name, name.Length(), &block_name)) {
    LOG(ERROR) << "Failed to convert symbol name to UTF8.";
    return false;
  }

  // Find the block to which this symbol maps, and ensure it fully covers the
  // symbol.
  RelativeAddress block_addr(rva);
  BlockGraph::Block* block = image_->GetBlockByAddress(block_addr);
  if (block == NULL) {
    LOG(ERROR) << "No block found for function/thunk symbol \""
               << block_name << "\".";
    return false;
  }
  if (block->addr() + block->size() < block_addr + length) {
    LOG(ERROR) << "Section contribution \"" << block->name() << "\" does not "
               << "fully cover function/thunk symbol \"" << block_name << "\".";
    return false;
  }

  // Annotate the block with a label, as this is an entry point to it. This is
  // the routine that adds labels, so there should never be any collisions.
  CHECK(AddLabelToBlock(block_addr, block_name, BlockGraph::CODE_LABEL, block));

  // If we didn't get an explicit no-return flag from the symbols check our
  // list of exceptions.
  if (no_return == FALSE && non_returning_functions_.count(block->name()) > 0) {
    VLOG(1) << "Forcing non-returning attribute on function \""
            << block->name() << "\".";
    no_return = TRUE;
  }

  // Set the block attributes.
  if (no_return == TRUE)
    block->set_attribute(BlockGraph::NON_RETURN_FUNCTION);
  if (has_inl_asm == TRUE)
    block->set_attribute(BlockGraph::HAS_INLINE_ASSEMBLY);
  if (has_eh || has_seh)
    block->set_attribute(BlockGraph::HAS_EXCEPTION_HANDLING);
  if (IsSymTag(function, SymTagThunk))
    block->set_attribute(BlockGraph::THUNK);

  if (!CreateLabelsForFunction(function, block)) {
    LOG(ERROR) << "Failed to create labels for '" << block->name() << "'.";
    return false;
  }

  return true;
}

bool OldDecomposer::CreateLabelsForFunction(IDiaSymbol* function,
                                         BlockGraph::Block* block) {
  DCHECK(function != NULL);
  DCHECK(block != NULL);

  // Lookup the block address.
  RelativeAddress block_addr;
  if (!image_->GetAddressOf(block, &block_addr)) {
    NOTREACHED() << "Block " << block->name() << " has no address.";
    return false;
  }

  // Enumerate all symbols which are children of function.
  ScopedComPtr<IDiaEnumSymbols> dia_enum_symbols;
  HRESULT hr = function->findChildren(SymTagNull,
                                      NULL,
                                      nsNone,
                                      dia_enum_symbols.Receive());
  if (FAILED(hr)) {
    LOG(ERROR) << "Failed to get the DIA label enumerator: "
               << com::LogHr(hr) << ".";
    return false;
  }

  while (true) {
    ScopedComPtr<IDiaSymbol> symbol;
    ULONG fetched = 0;
    hr = dia_enum_symbols->Next(1, symbol.Receive(), &fetched);
    if (FAILED(hr)) {
      LOG(ERROR) << "Failed to enumerate the DIA symbol: "
                 << com::LogHr(hr) << ".";
      return false;
    }
    if (hr != S_OK || fetched == 0)
      break;

    // If it doesn't have an RVA then it's not interesting to us.
    DWORD temp_rva = 0;
    if (symbol->get_relativeVirtualAddress(&temp_rva) != S_OK)
      continue;

    // Get the type of symbol we're looking at.
    DWORD temp_sym_tag = 0;
    if (symbol->get_symTag(&temp_sym_tag) != S_OK) {
      LOG(ERROR) << "Failed to retrieve label information.";
      return false;
    }

    enum SymTagEnum sym_tag = static_cast<enum SymTagEnum>(temp_sym_tag);

#if defined(_MSC_VER) && (_MSC_VER >= 1700)
    // Since VS 2012 there's some new symbols exposed by DIA which are not
    // handled at the moment.
    // TODO(sebmarchand): Handle those symbols.
    if (sym_tag == SymTagInlineSite || sym_tag == SymTagCallee)
      continue;
#endif

    BlockGraph::LabelAttributes label_attr = SymTagToLabelAttributes(sym_tag);

    // TODO(rogerm): Add a flag to include/exclude the symbol types that are
    //     interesting for debugging purposes, but not actually needed for
    //     decomposition: FuncDebugStart/End, Block, etc.

    // We ignore labels that fall outside of the code block. We sometimes
    // get labels at the end of a code block, and if the binary has any OMAP
    // information these follow the original successor block, and they can
    // end up most anywhere in the binary.
    RelativeAddress label_rva(temp_rva);
    if (label_rva < block_addr || label_rva >= block_addr + block->size())
      continue;

    // Extract the symbol's name.
    std::string label_name;
    {
      ScopedBstr temp_name;
      if (symbol->get_name(temp_name.Receive()) == S_OK &&
          !WideToUTF8(temp_name, temp_name.Length(), &label_name)) {
        LOG(ERROR) << "Failed to convert label name to UTF8.";
        return false;
      }
    }

    // Not all symbols have a name, if we've found one without a name, make
    // one up.
    BlockGraph::Offset offset = label_rva - block_addr;
    if (label_name.empty()) {
      switch (sym_tag) {
        case SymTagFuncDebugStart: {
          label_name = "<debug-start>";
          break;
        }

        case SymTagFuncDebugEnd: {
          label_name = "<debug-end>";
          break;
        }

        case SymTagData: {
          if (reloc_set_.count(label_rva)) {
            label_name = base::StringPrintf("<jump-table-%d>", offset);
            label_attr |= BlockGraph::JUMP_TABLE_LABEL;
          } else {
            label_name = base::StringPrintf("<case-table-%d>", offset);
            label_attr |= BlockGraph::CASE_TABLE_LABEL;
          }
          break;
        }

        case SymTagBlock: {
          label_name = "<scope-start>";
          break;
        }

        // The DIA SDK shipping with MSVS 2010 includes additional symbol types.
        case SymTagCallSite: {
          label_name = "<call-site>";
          break;
        }

        default: {
          LOG(WARNING) << "Unexpected symbol type " << sym_tag << " in "
                       << block->name() << " at "
                       << base::StringPrintf("0x%08X.", label_rva.value());
          label_name = base::StringPrintf("<anonymous-%d>", sym_tag);
        }
      }
    }

    // We expect that we'll never see a code label that refers to a reloc.
    // This happens sometimes, however, as we generally get a code label for
    // the first byte after a switch statement. This can sometimes land on the
    // following jump table.
    if ((label_attr & BlockGraph::CODE_LABEL) && reloc_set_.count(label_rva)) {
      VLOG(1) << "Collision between reloc and code label in "
              << block->name() << " at " << label_name
              << base::StringPrintf(" (0x%08X).", label_rva.value())
              << " Falling back to data label.";
      label_attr = BlockGraph::DATA_LABEL | BlockGraph::JUMP_TABLE_LABEL;
      DCHECK_EQ(block_addr, block->addr());
      BlockGraph::Label label;
      if (block->GetLabel(offset, &label) &&
          !label.has_attributes(BlockGraph::DATA_LABEL)) {
        VLOG(1) << block->name() << ": Replacing label " << label.name()
                << " ("
                << BlockGraph::LabelAttributesToString(label.attributes())
                << ") at offset " << offset << ".";
        block->RemoveLabel(offset);
      }
    }

    // Add the label to the block.
    if (!AddLabelToBlock(label_rva, label_name, label_attr, block)) {
      LOG(ERROR) << "Failed to add label to code block.";
      return false;
    }

    // Is this a scope? Then it also has a length. Use it to create the matching
    // scope end.
    if (sym_tag == SymTagBlock) {
      ULONGLONG length = 0;
      if (symbol->get_length(&length) != S_OK) {
        LOG(ERROR) << "Failed to extract code scope length for "
                   << block->name();
        return false;
      }
      label_rva += length;
      label_name = "<scope-end>";
      label_attr = BlockGraph::SCOPE_END_LABEL;
      if (!AddLabelToBlock(label_rva, label_name, label_attr, block)) {
        LOG(ERROR) << "Failed to add label to code block.";
        return false;
      }
    }
  }

  return true;
}

bool OldDecomposer::ProcessThunkSymbols(IDiaSymbol* globals) {
  ScopedComPtr<IDiaEnumSymbols> enum_compilands;
  HRESULT hr = globals->findChildren(SymTagCompiland,
                                     NULL,
                                     nsNone,
                                     enum_compilands.Receive());
  if (FAILED(hr)) {
    LOG(ERROR) << "Failed to retrieve compiland enumerator: "
               << com::LogHr(hr) << ".";
    return false;
  }

  while (true) {
    ScopedComPtr<IDiaSymbol> compiland;
    ULONG fetched = 0;
    hr = enum_compilands->Next(1, compiland.Receive(), &fetched);
    if (FAILED(hr)) {
      LOG(ERROR) << "Failed to enumerate compiland enumerator: "
                 << com::LogHr(hr) << ".";
      return false;
    }
    if (hr != S_OK || fetched == 0)
      break;

    ScopedComPtr<IDiaEnumSymbols> enum_thunks;
    hr = compiland->findChildren(SymTagThunk,
                                 NULL,
                                 nsNone,
                                 enum_thunks.Receive());
    if (FAILED(hr)) {
      LOG(ERROR) << "Failed to retrieve thunk enumerator: "
                 << com::LogHr(hr) << ".";
      return false;
    }

    while (true) {
      ScopedComPtr<IDiaSymbol> thunk;
      hr = enum_thunks->Next(1, thunk.Receive(), &fetched);
      if (FAILED(hr)) {
        LOG(ERROR) << "Failed to enumerate thunk enumerator: "
                   << com::LogHr(hr) << ".";
        return false;
      }
      if (hr != S_OK || fetched == 0)
        break;

      DCHECK(IsSymTag(thunk, SymTagThunk));

      if (!ProcessFunctionOrThunkSymbol(thunk))
        return false;
    }
  }

  return true;
}

bool OldDecomposer::CreateGlobalLabels(IDiaSymbol* globals) {
  ScopedComPtr<IDiaEnumSymbols> enum_compilands;
  HRESULT hr = globals->findChildren(SymTagCompiland,
                                     NULL,
                                     nsNone,
                                     enum_compilands.Receive());
  if (FAILED(hr)) {
    LOG(ERROR) << "Failed to retrieve compiland enumerator: "
               << com::LogHr(hr) << ".";
    return false;
  }

  while (true) {
    ScopedComPtr<IDiaSymbol> compiland;
    ULONG fetched = 0;
    hr = enum_compilands->Next(1, compiland.Receive(), &fetched);
    if (FAILED(hr)) {
      LOG(ERROR) << "Failed to enumerate compiland enumerator: "
                 << com::LogHr(hr) << ".";
      return false;
    }
    if (hr != S_OK || fetched == 0)
      break;

    ScopedComPtr<IDiaEnumSymbols> enum_labels;
    hr = compiland->findChildren(SymTagLabel,
                                 NULL,
                                 nsNone,
                                 enum_labels.Receive());
    if (FAILED(hr)) {
      LOG(ERROR) << "Failed to retrieve label enumerator: "
                 << com::LogHr(hr) << ".";
      return false;
    }

    while (true) {
      ScopedComPtr<IDiaSymbol> label;
      hr = enum_labels->Next(1, label.Receive(), &fetched);
      if (FAILED(hr)) {
        LOG(ERROR) << "Failed to enumerate label enumerator: "
                   << com::LogHr(hr) << ".";
        return false;
      }
      if (hr != S_OK || fetched == 0)
        break;

      DCHECK(IsSymTag(label, SymTagLabel));

      DWORD addr = 0;
      ScopedBstr temp_name;
      if (label->get_relativeVirtualAddress(&addr) != S_OK ||
          label->get_name(temp_name.Receive()) != S_OK) {
        LOG(ERROR) << "Failed to retrieve label address or name.";
        return false;
      }

      std::string label_name;
      if (!WideToUTF8(temp_name, temp_name.Length(), &label_name)) {
        LOG(ERROR) << "Failed to convert label name to UTF8.";
        return false;
      }

      RelativeAddress label_addr(addr);
      BlockGraph::Block* block = image_->GetBlockByAddress(label_addr);
      if (block == NULL) {
        LOG(ERROR) << "No block for label " << label_name << " at " << addr;
        return false;
      }

      if (!AddLabelToBlock(label_addr,
                           label_name,
                           BlockGraph::CODE_LABEL,
                           block)) {
        LOG(ERROR) << "Failed to add label to code block.";
        return false;
      }
    }
  }

  return true;
}

bool OldDecomposer::CreateGapBlock(BlockGraph::BlockType block_type,
                                RelativeAddress address,
                                BlockGraph::Size size) {
  BlockGraph::Block* block = FindOrCreateBlock(block_type, address, size,
      base::StringPrintf("Gap Block 0x%08X", address.value()).c_str(),
      kExpectNoBlock);
  if (block == NULL) {
    LOG(ERROR) << "Unable to create gap block.";
    return false;
  }
  block->set_attribute(BlockGraph::GAP_BLOCK);

  return true;
}

bool OldDecomposer::CreateSectionGapBlocks(const IMAGE_SECTION_HEADER* header,
                                        BlockGraph::BlockType block_type) {
  RelativeAddress section_begin(header->VirtualAddress);
  RelativeAddress section_end(section_begin + header->Misc.VirtualSize);
  RelativeAddress image_end(
      image_file_.nt_headers()->OptionalHeader.SizeOfImage);

  // Search for the first and last blocks interesting from the start and end
  // of the section to the end of the image.
  BlockGraph::AddressSpace::RangeMap::const_iterator it(
      image_->address_space_impl().FindFirstIntersection(
          BlockGraph::AddressSpace::Range(section_begin,
                                          image_end - section_begin)));

  BlockGraph::AddressSpace::RangeMap::const_iterator end =
      image_->address_space_impl().end();
  if (section_end < image_end) {
    end = image_->address_space_impl().FindFirstIntersection(
        BlockGraph::AddressSpace::Range(section_end,
                                        image_end - section_end));
  }

  // The whole section is missing. Cover it with one gap block.
  if (it == end)
    return CreateGapBlock(
        block_type, section_begin, section_end - section_begin);

  // Create the head gap block if need be.
  if (section_begin < it->first.start())
    if (!CreateGapBlock(
        block_type, section_begin, it->first.start() - section_begin))
      return false;

  // Now iterate the blocks and fill in gaps.
  for (; it != end; ++it) {
    const BlockGraph::Block* block = it->second;
    DCHECK(block != NULL);
    RelativeAddress block_end = it->first.start() + block->size();
    if (block_end >= section_end)
      break;

    // Walk to the next address in turn.
    BlockGraph::AddressSpace::RangeMap::const_iterator next = it;
    ++next;
    if (next == end) {
      // We're at the end of the list. Create the tail gap block.
      DCHECK_GT(section_end, block_end);
      if (!CreateGapBlock(block_type, block_end, section_end - block_end))
        return false;
      break;
    }

    // Create the interstitial gap block.
    if (block_end < next->first.start())
      if (!CreateGapBlock(
          block_type, block_end, next->first.start() - block_end))
        return false;
  }

  return true;
}

bool OldDecomposer::CreateGapBlocks() {
  size_t num_sections = image_file_.nt_headers()->FileHeader.NumberOfSections;

  // Iterate through all the image sections.
  for (size_t i = 0; i < num_sections; ++i) {
    const IMAGE_SECTION_HEADER* header = image_file_.section_header(i);
    DCHECK(header != NULL);

    BlockGraph::BlockType type = BlockGraph::CODE_BLOCK;
    const char* section_type = NULL;
    switch (GetSectionType(header)) {
      case kSectionCode:
        type = BlockGraph::CODE_BLOCK;
        section_type = "code";
        break;

      case kSectionData:
        type = BlockGraph::DATA_BLOCK;
        section_type = "data";
        break;

      default:
        continue;
    }

    if (!CreateSectionGapBlocks(header, type)) {
      LOG(ERROR) << "Unable to create gap blocks for " << section_type
                 << " section \"" << header->Name << "\".";
      return false;
    }
  }

  return true;
}

bool OldDecomposer::AddReferenceCallback(RelativeAddress src_addr,
                                      BlockGraph::ReferenceType type,
                                      BlockGraph::Size size,
                                      RelativeAddress dst_addr) {
  // This is only called by the PEFileParser, and it creates some references
  // for which there are no corresponding fixup entries.
  return ValidateOrAddReference(FIXUP_MAY_EXIST, src_addr, type, size, dst_addr,
                                0, &fixup_map_, &references_);
}

bool OldDecomposer::ParseRelocs() {
  if (!image_file_.DecodeRelocs(&reloc_set_)) {
    LOG(ERROR) << "Unable to decode image relocs.";
    return false;
  }

  PEFile::RelocMap reloc_map;
  if (!image_file_.ReadRelocs(reloc_set_, &reloc_map)) {
    LOG(ERROR) << "Unable to read image relocs.";
    return false;
  }

  // Validate each relocation entry against the corresponding fixup entry.
  if (!ValidateRelocs(reloc_map))
    return false;

  return true;
}

bool OldDecomposer::CreateReferencesFromFixups() {
  FixupMap::const_iterator it(fixup_map_.begin());
  for (; it != fixup_map_.end(); ++it) {
    RelativeAddress src_addr(it->second.location);
    uint32 data = 0;
    if (!image_file_.ReadImage(src_addr, &data, sizeof(data))) {
      LOG(ERROR) << "Unable to read image data for fixup with source at "
                 << src_addr;
      return false;
    }

    RelativeAddress dst_base(it->second.base);
    BlockGraph::Offset dst_offset = 0;
    switch (it->second.type) {
      case BlockGraph::PC_RELATIVE_REF: {
        dst_offset = src_addr + kPointerSize + data - dst_base;
        break;
      }

      case BlockGraph::ABSOLUTE_REF: {
        dst_offset = image_file_.AbsToRelDisplacement(data) - dst_base.value();
        break;
      }

      case BlockGraph::RELATIVE_REF: {
        dst_offset = data - dst_base.value();
        break;
      }

      default: {
        NOTREACHED() << "Invalid reference type.";
        return false;
      }
    }

    if (!AddReference(src_addr, it->second.type, kPointerSize, dst_base,
                      dst_offset, &references_)) {
      return false;
    }
  }

  return true;
}

bool OldDecomposer::ValidateRelocs(const PEFile::RelocMap& reloc_map) {
  PEFile::RelocMap::const_iterator it(reloc_map.begin());
  PEFile::RelocMap::const_iterator end(reloc_map.end());
  for (; it != end; ++it) {
    RelativeAddress src(it->first);
    RelativeAddress dummy;

    if (!ValidateOrAddReference(
            FIXUP_MUST_EXIST, src, BlockGraph::ABSOLUTE_REF,
            sizeof(dummy), dummy, 0, &fixup_map_, &references_)) {
      return false;
    }
  }

  return true;
}

bool OldDecomposer::CreateBlocksFromSectionContribs(IDiaSession* session) {
  ScopedComPtr<IDiaEnumSectionContribs> section_contribs;
  SearchResult search_result = FindDiaTable(session,
                                            section_contribs.Receive());
  if (search_result != kSearchSucceeded) {
    if (search_result == kSearchFailed)
      LOG(ERROR) << "No section contribution table found.";
    return false;
  }

  size_t rsrc_id = image_file_.GetSectionIndex(kResourceSectionName);

  LONG count = 0;
  if (section_contribs->get_Count(&count) != S_OK) {
    LOG(ERROR) << "Failed to get section contributions enumeration length.";
    return false;
  }

  for (LONG visited = 0; visited < count; ++visited) {
    ScopedComPtr<IDiaSectionContrib> section_contrib;
    ULONG fetched = 0;
    HRESULT hr = section_contribs->Next(1, section_contrib.Receive(), &fetched);
    if (hr != S_OK) {
      LOG(ERROR) << "Failed to get DIA section contribution: "
                 << com::LogHr(hr) << ".";
      return false;
    }
    if (fetched == 0)
      break;

    hr = E_FAIL;
    DWORD rva = 0;
    DWORD length = 0;
    DWORD section_id = 0;
    BOOL code = FALSE;
    ScopedComPtr<IDiaSymbol> compiland;
    ScopedBstr bstr_name;
    if ((hr = section_contrib->get_relativeVirtualAddress(&rva)) != S_OK ||
        (hr = section_contrib->get_length(&length)) != S_OK ||
        (hr = section_contrib->get_addressSection(&section_id)) != S_OK ||
        (hr = section_contrib->get_code(&code)) != S_OK ||
        (hr = section_contrib->get_compiland(compiland.Receive())) != S_OK ||
        (hr = compiland->get_name(bstr_name.Receive())) != S_OK) {
      LOG(ERROR) << "Failed to get section contribution properties: "
                 << com::LogHr(hr) << ".";
      return false;
    }

    // Determine if this function was built by a supported compiler.
    bool is_built_by_supported_compiler =
        IsBuiltBySupportedCompiler(compiland.get());

    // DIA numbers sections from 1 to n, while we do 0 to n - 1.
    DCHECK_LT(0u, section_id);
    --section_id;

    // We don't parse the resource section, as it is parsed by the PEFileParser.
    if (section_id == rsrc_id)
      continue;

    std::string name;
    if (!WideToUTF8(bstr_name, bstr_name.Length(), &name)) {
      LOG(ERROR) << "Failed to convert compiland name to UTF8.";
      return false;
    }

    // Create the block.
    BlockGraph::BlockType block_type =
        code ? BlockGraph::CODE_BLOCK : BlockGraph::DATA_BLOCK;
    BlockGraph::Block* block = FindOrCreateBlock(block_type,
                                                 RelativeAddress(rva),
                                                 length,
                                                 name.c_str(),
                                                 kExpectNoBlock);
    if (block == NULL) {
      LOG(ERROR) << "Unable to create block.";
      return false;
    }

    // Set the block compiland name.
    block->set_compiland_name(name);

    // Set the block attributes.
    block->set_attribute(BlockGraph::SECTION_CONTRIB);
    if (!is_built_by_supported_compiler)
      block->set_attribute(BlockGraph::BUILT_BY_UNSUPPORTED_COMPILER);
  }

  return true;
}

DiaBrowser::BrowserDirective OldDecomposer::OnDataSymbol(
    const DiaBrowser& dia_browser,
    const DiaBrowser::SymTagVector& sym_tags,
    const DiaBrowser::SymbolPtrVector& symbols) {
  DCHECK_LT(0u, sym_tags.size());
  DCHECK_EQ(sym_tags.size(), symbols.size());
  DCHECK_EQ(SymTagData, sym_tags.back());

  const DiaBrowser::SymbolPtr& data(symbols.back());

  HRESULT hr = E_FAIL;
  DWORD location_type = LocIsNull;
  DWORD rva = 0;
  ScopedBstr name_bstr;
  if (FAILED(hr = data->get_locationType(&location_type)) ||
      FAILED(hr = data->get_relativeVirtualAddress(&rva)) ||
      FAILED(hr = data->get_name(name_bstr.Receive()))) {
    LOG(ERROR) << "Failed to get data properties: " << com::LogHr(hr) << ".";
    return DiaBrowser::kBrowserAbort;
  }

  // We only parse data symbols with static storage.
  if (location_type != LocIsStatic)
    return DiaBrowser::kBrowserContinue;

  // Symbols with an address of zero are essentially invalid. They appear to
  // have been optimized away by the compiler, but they are still reported.
  if (rva == 0)
    return DiaBrowser::kBrowserContinue;

  // TODO(chrisha): We eventually want to get alignment info from the type
  //     information. This is strictly a lower bound, however, as certain
  //     data may be used in instructions that impose stricter alignment
  //     requirements.
  size_t length = 0;
  if (!GetTypeInfo(data, &length)) {
    return DiaBrowser::kBrowserAbort;
  }
  // Zero-length data symbols act as 'forward declares' in some sense. They
  // are always followed by a non-zero length data symbol with the same name
  // and location.
  if (length == 0)
    return DiaBrowser::kBrowserContinue;

  RelativeAddress addr(rva);
  std::string name;
  if (!WideToUTF8(name_bstr, name_bstr.Length(), &name)) {
    LOG(ERROR) << "Failed to convert data symbol name to UTF8.";
    return DiaBrowser::kBrowserAbort;
  }

  // In general we expect data symbols to be completely contained by a block.
  // The data symbol can exceed the size of the block in the case of data
  // imports. For some reason the toolchain emits a global data symbol with
  // type information equal to the type of the data *pointed* to by the import
  // entry rather than the type of the entry itself. Thus, if the data type
  // is bigger than the entire IAT this symbol will exceed it. To complicate
  // matters even more, a poorly written module can import its own export in
  // which case a linker generated pseudo-import-entry block will be
  // generated. This won't be part of the IAT, so we can't even filter based
  // on that. Instead, we simply ignore global data symbols that exceed the
  // block size.
  FindOrCreateBlockDirective directive = kAllowCoveringBlock;
  base::StringPiece spname(name);
  if (sym_tags.size() == 1 && spname.starts_with("_imp_")) {
    // For global data symbols (no parent symbols) to imported data ("_imp_"
    // prefix) we allow partially covering blocks.
    directive = kAllowPartialCoveringBlock;
  }

  BlockGraph::Block* block = FindOrCreateBlock(BlockGraph::DATA_BLOCK,
                                               addr, length, spname,
                                               directive);

  // We've seen null blocks for some symbols in modules compiled using a custom
  // non-Microsoft toolchain.
  if (block == NULL) {
    LOG(ERROR) << "Failed to get a block for symbol named " << name << ".";
    return DiaBrowser::kBrowserAbort;
  }

  if (block->type() == BlockGraph::CODE_BLOCK) {
    // The NativeClient bits of chrome.dll consists of hand-written assembly
    // that is compiled using a custom non-Microsoft toolchain. Unfortunately
    // for us this toolchain emits 1-byte data symbols instead of code labels.
    static const char kNaClPrefix[] = "NaCl";
    if (length == 1 &&
        name.compare(0, arraysize(kNaClPrefix) - 1, kNaClPrefix) == 0) {
      if (!AddLabelToBlock(addr, name, BlockGraph::CODE_LABEL, block)) {
        LOG(ERROR) << "Failed to add label to code block.";
        return DiaBrowser::kBrowserAbort;
      }

      return DiaBrowser::kBrowserContinue;
    }
  }

  if (!AddLabelToBlock(addr, name, BlockGraph::DATA_LABEL, block)) {
    LOG(ERROR) << "Failed to add data label to block.";
    return DiaBrowser::kBrowserAbort;
  }

  return DiaBrowser::kBrowserContinue;
}

DiaBrowser::BrowserDirective OldDecomposer::OnPublicSymbol(
    const DiaBrowser& dia_browser,
    const DiaBrowser::SymTagVector& sym_tags,
    const DiaBrowser::SymbolPtrVector& symbols) {
  DCHECK_LT(0u, sym_tags.size());
  DCHECK_EQ(sym_tags.size(), symbols.size());
  DCHECK_EQ(SymTagPublicSymbol, sym_tags.back());
  const DiaBrowser::SymbolPtr& symbol(symbols.back());

  // We don't care about symbols that don't have addresses.
  DWORD rva = 0;
  if (S_OK != symbol->get_relativeVirtualAddress(&rva))
    return DiaBrowser::kBrowserContinue;

  ScopedBstr name_bstr;
  if (S_OK != symbol->get_name(name_bstr.Receive())) {
    LOG(ERROR) << "Failed to get public symbol name.";
    return DiaBrowser::kBrowserAbort;
  }

  std::string name;
  if (!WideToUTF8(name_bstr, name_bstr.Length(), &name)) {
    LOG(ERROR) << "Failed to convert symbol name to UTF8.";
    return DiaBrowser::kBrowserAbort;
  }

  RelativeAddress addr(rva);
  BlockGraph::Block* block = image_->GetBlockByAddress(addr);
  if (block == NULL) {
    LOG(ERROR) << "No block found for public symbol \"" << name << "\".";
    return DiaBrowser::kBrowserAbort;
  }

  // Public symbol names are mangled. Remove leading '_' as per
  // http://msdn.microsoft.com/en-us/library/00kh39zz(v=vs.80).aspx
  if (name[0] == '_')
    name = name.substr(1);

  if (!AddLabelToBlock(addr, name, BlockGraph::PUBLIC_SYMBOL_LABEL, block))
    return DiaBrowser::kBrowserAbort;

  return DiaBrowser::kBrowserContinue;
}

bool OldDecomposer::ProcessStaticInitializers() {
  typedef std::pair<RelativeAddress, RelativeAddress> AddressPair;
  typedef std::map<std::string, AddressPair> AddressPairMap;

  const RelativeAddress kNull(0);

  // This stores pairs of addresses, representing the beginning and the end
  // of each static initializer block. It is keyed with a string, which is
  // returned by the match group of the corresponding initializer pattern.
  // The key is necessary to correlate matching labels (as multiple pairs
  // of labels may match through a single pattern).
  AddressPairMap addr_pair_map;

  // Used for keeping track of which label, if any, we matched.
  enum MatchType {
    kMatchNone,
    kMatchBeginLabel,
    kMatchEndLabel
  };

  // Iterate through all data blocks, looking for known initializer labels.
  BlockGraph::AddressSpace::RangeMapConstIter block_it = image_->begin();
  for (; block_it != image_->end(); ++block_it) {
    const BlockGraph::Block* block = block_it->second;
    // Skip non-data blocks.
    if (block->type() != BlockGraph::DATA_BLOCK)
      continue;

    // Check the block name against each of the initializer patterns.
    MatchType match = kMatchNone;
    std::string block_name = block->name();
    std::string name;
    for (size_t i = 0; i < static_initializer_patterns_.size(); ++i) {
      REPair& re_pair(static_initializer_patterns_[i]);
      if (re_pair.first.FullMatch(block_name, &name))
        match = kMatchBeginLabel;
      else if (re_pair.second.FullMatch(block_name, &name))
        match = kMatchEndLabel;

      if (match != kMatchNone)
        break;
    }

    // No pattern matched this symbol? Continue to the next one.
    if (match == kMatchNone)
      continue;

    // Ensure this symbol exists in the map. Thankfully, addresses default
    // construct to NULL.
    AddressPair& addr_pair = addr_pair_map[name];

    // Update the bracketing symbol endpoint. Make sure each symbol endpoint
    // is only seen once.
    RelativeAddress* addr = NULL;
    RelativeAddress new_addr;
    if (match == kMatchBeginLabel) {
      addr = &addr_pair.first;
      new_addr = block->addr();
    } else {
      addr = &addr_pair.second;
      new_addr = block->addr() + block->size();
    }
    if (*addr != kNull) {
      LOG(ERROR) << "Bracketing symbol appears multiple times: "
                 << block_name;
      return false;
    }
    *addr = new_addr;
  }

  // Use the bracketing symbols to make the initializers contiguous.
  AddressPairMap::const_iterator init_it = addr_pair_map.begin();
  for (; init_it != addr_pair_map.end(); ++init_it) {
    RelativeAddress begin_addr = init_it->second.first;
    if (begin_addr == kNull) {
      LOG(ERROR) << "Bracketing start symbol missing: " << init_it->first;
      return false;
    }

    RelativeAddress end_addr = init_it->second.second;
    if (end_addr == kNull) {
      LOG(ERROR) << "Bracketing end symbol missing: " << init_it->first;
      return false;
    }

    if (begin_addr > end_addr) {
      LOG(ERROR) << "Bracketing symbols out of order: " << init_it->first;
      return false;
    }

    // Merge the initializers.
    DataSpace::Range range(begin_addr, end_addr - begin_addr);
    BlockGraph::Block* merged = image_->MergeIntersectingBlocks(range);
    std::string name = base::StringPrintf("Bracketed Initializers: %s",
                                          init_it->first.c_str());
    DCHECK(merged != NULL);
    merged->set_name(name);
    merged->set_attribute(BlockGraph::COFF_GROUP);
  }

  return true;
}

bool OldDecomposer::ProcessDataSymbols(IDiaSymbol* root) {
  DiaBrowser::MatchCallback on_data_symbol(
      base::Bind(&OldDecomposer::OnDataSymbol, base::Unretained(this)));

  DiaBrowser dia_browser;
  dia_browser.AddPattern(Seq(Opt(SymTagCompiland), SymTagData),
                         on_data_symbol);
  dia_browser.AddPattern(Seq(SymTagCompiland, SymTagFunction,
                             Star(SymTagBlock), SymTagData),
                         on_data_symbol);

  return dia_browser.Browse(root);
}

bool OldDecomposer::ProcessPublicSymbols(IDiaSymbol* root) {
  DiaBrowser::MatchCallback on_public_symbol(
      base::Bind(&OldDecomposer::OnPublicSymbol, base::Unretained(this)));

  DiaBrowser dia_browser;
  dia_browser.AddPattern(SymTagPublicSymbol, on_public_symbol);

  return dia_browser.Browse(root);
}

bool OldDecomposer::GuessDataBlockAlignments() {
  size_t num_sections = image_file_.nt_headers()->FileHeader.NumberOfSections;
  // Iterate through all the image sections.
  for (size_t i = 0; i < num_sections; ++i) {
    const IMAGE_SECTION_HEADER* header = image_file_.section_header(i);
    DCHECK(header != NULL);

    // Only iterate through data sections.
    if (GetSectionType(header) != kSectionData)
      continue;

    RelativeAddress section_begin(header->VirtualAddress);
    size_t section_length = header->Misc.VirtualSize;

    // Get the range of blocks in this section.
    BlockGraph::AddressSpace::RangeMapIterPair it_pair =
        image_->GetIntersectingBlocks(section_begin, section_length);

    // Iterate through the blocks in the section, setting their alignment.
    BlockGraph::AddressSpace::RangeMapIter it = it_pair.first;
    for (; it != it_pair.second; ++it) {
      BlockGraph::Block* block = it->second;
      GuessDataBlockAlignment(block,
          image_file_.nt_headers()->OptionalHeader.SectionAlignment);
    }
  }

  return true;
}

bool OldDecomposer::CreateCodeReferences() {
  BlockGraph::BlockMap::iterator it(image_->graph()->blocks_mutable().begin());
  BlockGraph::BlockMap::iterator end(image_->graph()->blocks_mutable().end());
  for (; it != end; ++it) {
    BlockGraph::Block* block = &it->second;

    if (block->type() != BlockGraph::CODE_BLOCK)
      continue;

    // We shouldn't attempt disassembly on unsafe blocks. The new decomposer
    // has this fixed, but this is a workaround here for now.
    if (!pe::PETransformPolicy::CodeBlockAttributesAreBasicBlockSafe(
            block, false)) {
      continue;
    }

    if (!CreateCodeReferencesForBlock(block))
      return false;
  }

  return true;
}

bool OldDecomposer::CreateCodeReferencesForBlock(BlockGraph::Block* block) {
  DCHECK(current_block_ == NULL);
  current_block_ = block;

  RelativeAddress block_addr;
  if (!image_->GetAddressOf(block, &block_addr)) {
    LOG(ERROR) << "Block \"" << block->name() << "\" has no address.";
    return false;
  }

  AbsoluteAddress abs_block_addr;
  if (!image_file_.Translate(block_addr, &abs_block_addr)) {
    LOG(ERROR) << "Unable to get absolute address for " << block_addr;
    return false;
  }

  Disassembler::InstructionCallback on_instruction(
      base::Bind(&OldDecomposer::OnInstruction, base::Unretained(this)));

  // Use block labels and code references as starting points for disassembly.
  Disassembler::AddressSet starting_points;
  GetDisassemblyStartingPoints(block, abs_block_addr, reloc_set_,
                               &starting_points);

  // If the block has no starting points, then it has no private symbols and
  // is not BB safe. We mark the block as not safe for basic-block disassembly.
  if (starting_points.empty() &&
      (block->attributes() & BlockGraph::GAP_BLOCK) == 0) {
    VLOG(1) << "Block \"" << block->name() << "\" has no private symbols.";
    block->set_attribute(BlockGraph::ERRORED_DISASSEMBLY);
  }

  // Determine whether or not we are being strict with disassembly.
  // NOTE: This is particularly ugly. OldDecomposer should not depend on the
  //     transform policy object. In fact, OldDecomposer should not even be
  //     doing disassembly. This all disappears in the new decomposer.
  bool strict = PETransformPolicy::CodeBlockAttributesAreBasicBlockSafe(
      block, false);
  be_strict_with_current_block_ = false;

  // Determine the length of the code portion of the block by trimming off any
  // known trailing data. Also, if we're in strict mode, ensure that our
  // assumption regarding code/data layout is met.
  size_t code_size = 0;
  if (!BlockHasExpectedCodeDataLayout(block, &code_size) &&
      be_strict_with_current_block_) {
    LOG(ERROR) << "Block \"" << block->name() << "\" has unexpected code/data "
               << "layout.";
    return false;
  }

  // Disassemble the block.
  Disassembler disasm(block->data(),
                      code_size,
                      abs_block_addr,
                      starting_points,
                      on_instruction);
  Disassembler::WalkResult result = disasm.Walk();

  // If we're strict (that is, we're confident that the block was produced by
  // cl.exe), then we can use that knowledge to look for calls that appear to be
  // to non-returning functions that we may not have symbol info for.
  if (be_strict_with_current_block_)
    LookForNonReturningFunctions(references_, *image_, current_block_, disasm);

  DCHECK_EQ(block, current_block_);
  current_block_ = NULL;
  be_strict_with_current_block_ = true;

  switch (result) {
    case Disassembler::kWalkIncomplete:
      // There were computed branches that couldn't be chased down.
      block->set_attribute(BlockGraph::INCOMPLETE_DISASSEMBLY);
      return true;

    case Disassembler::kWalkTerminated:
      // This exit condition should only ever occur for non-strict disassembly.
      // If strict, we should always get kWalkError.
      DCHECK(!strict);
      // This means that they code was malformed, or broke some expected
      // conventions. This code is not safe for basic block disassembly.
      block->set_attribute(BlockGraph::ERRORED_DISASSEMBLY);
      return true;

    case Disassembler::kWalkSuccess:
      // Were any bytes in the block not accounted for? This generally means
      // unreachable code, which we see quite often, especially in debug builds.
      if (disasm.code_size() != disasm.disassembled_bytes())
        block->set_attribute(BlockGraph::INCOMPLETE_DISASSEMBLY);
      return true;

    case Disassembler::kWalkError:
      return false;

    default:
      NOTREACHED() << "Unhandled Disassembler WalkResult.";
      return false;
  }
}

BlockGraph::Block* OldDecomposer::CreateBlock(BlockGraph::BlockType type,
                                           RelativeAddress address,
                                           BlockGraph::Size size,
                                           const base::StringPiece& name) {
  BlockGraph::Block* block = image_->AddBlock(type, address, size, name);
  if (block == NULL) {
    LOG(ERROR) << "Unable to add block at " << address << " with size "
               << size << ".";
    return NULL;
  }

  // Mark the source range from whence this block originates.
  bool pushed = block->source_ranges().Push(
      BlockGraph::Block::DataRange(0, size),
      BlockGraph::Block::SourceRange(address, size));
  DCHECK(pushed);

  BlockGraph::SectionId section = image_file_.GetSectionIndex(address, size);
  if (section == BlockGraph::kInvalidSectionId) {
    LOG(ERROR) << "Block at " << address << " with size " << size
               << " lies outside of all sections.";
    return NULL;
  }
  block->set_section(section);

  const uint8* data = image_file_.GetImageData(address, size);
  if (data != NULL)
    block->SetData(data, size);

  return block;
}

BlockGraph::Block* OldDecomposer::FindOrCreateBlock(
    BlockGraph::BlockType type,
    RelativeAddress addr,
    BlockGraph::Size size,
    const base::StringPiece& name,
    FindOrCreateBlockDirective directive) {
  BlockGraph::Block* block = image_->GetBlockByAddress(addr);
  if (block != NULL) {
    // If we got a block we're guaranteed that it at least partially covers
    // the query range, so we can immediately return it in that case.
    if (directive == kAllowPartialCoveringBlock)
      return block;

    if (block->attributes() & BlockGraph::PE_PARSED) {
      // Always allow collisions where the new block is a proper subset of
      // an existing PE parsed block. The PE parser often knows more than we do
      // about blocks that need to stick together.
      directive = kAllowCoveringBlock;

      // Allow PE-parsed blocks to be grown to reflect reality. For example,
      // in VS2013 the linker makes space for 2 debug directories rather than
      // just one, and the symbols reflect this. We parse the debug directory
      // with the size indicated in the PE header, which conflicts with that
      // indicated by the section contributions.
      if (name == "* Linker *" && size > block->size()) {
        if (!image_->ResizeBlock(block, size)) {
          LOG(ERROR) << "Failed to extend PE parsed block with linker "
                     << "section contribution.";
          return false;
        }
        const uint8* data = image_file_.GetImageData(addr, size);
        block->SetData(data, size);
      }
    }

    bool collision = false;
    switch (directive) {
      case kExpectNoBlock: {
        collision = true;
        break;
      }
      case kAllowIdenticalBlock: {
        collision = (block->addr() != addr || block->size() != size);
        break;
      }
      default: {
        DCHECK(directive == kAllowCoveringBlock);
        collision = block->addr() > addr ||
            (block->addr() + block->size()) < addr + size;
        break;
      }
    }

    if (collision) {
      LOG(ERROR) << "Block collision for \"" << name.as_string() << "\" at "
                 << addr << "(" << size << ") with existing block \""
                 << block->name() << "\" at " << block->addr() << " ("
                 << block->size() << ").";
      return NULL;
    }

    return block;
  }
  DCHECK(block == NULL);

  return CreateBlock(type, addr, size, name);
}

CallbackDirective OldDecomposer::LookPastInstructionForData(
    RelativeAddress instr_end) {
  // If this instruction terminates at a data boundary (ie: the *next*
  // instruction will be data or a reloc), we can be certain that a new
  // lookup table is starting at this address.
  if (reloc_set_.find(instr_end) == reloc_set_.end())
    return Disassembler::kDirectiveContinue;

  // Find the block housing the reloc. We expect the reloc to be contained
  // completely within this block.
  BlockGraph::Block* block = image_->GetContainingBlock(instr_end, 4);
  if (block != current_block_) {
    CHECK(block != NULL);
    LOG_ERROR_OR_VLOG1(be_strict_with_current_block_)
        << "Found an instruction/data boundary between blocks: "
        << current_block_->name() << " and " << block->name();
    return AbortOrTerminateDisassembly(be_strict_with_current_block_);
  }

  BlockGraph::Offset offset = instr_end - block->addr();

  // We expect there to be a jump-table data label already.
  BlockGraph::Label label;
  bool have_label = block->GetLabel(offset, &label);
  if (!have_label || !label.has_attributes(
          BlockGraph::DATA_LABEL | BlockGraph::JUMP_TABLE_LABEL)) {
    LOG_ERROR_OR_VLOG1(be_strict_with_current_block_)
        << "Expected there to be a data label marking the jump "
        << "table at " << block->name() << " + " << offset << ".";

    // If we're in strict mode, we're a block that obeys standard conventions.
    // Which means we should already be aware of any jump tables in this block.
    if (be_strict_with_current_block_)
      return Disassembler::kDirectiveAbort;

    // If we're not in strict mode, add the jump-table label.
    if (have_label) {
      CHECK(block->RemoveLabel(offset));
    }

    CHECK(block->SetLabel(offset, BlockGraph::Label(
        base::StringPrintf("<JUMP-TABLE-%d>", offset),
        BlockGraph::DATA_LABEL | BlockGraph::JUMP_TABLE_LABEL)));
  }

  return Disassembler::kDirectiveTerminatePath;
}

void OldDecomposer::MarkDisassembledPastEnd() {
  DCHECK(current_block_ != NULL);
  current_block_->set_attribute(BlockGraph::DISASSEMBLED_PAST_END);
  // TODO(chrisha): The entire "disassembled past end" and non-returning
  //     function infrastructure can be ripped out once we rework the BB
  //     disassembler to be straight path, and remove the disassembly phase
  //     from the decomposer (where it's no longer needed). In the meantime
  //     we simply crank down this log verbosity due to all of the false
  //     positives.
  VLOG(1) << "Disassembled past end of block or into known data for block \""
          << current_block_->name() << "\" at " << current_block_->addr()
          << ".";
}

CallbackDirective OldDecomposer::VisitNonFlowControlInstruction(
    RelativeAddress instr_start, RelativeAddress instr_end) {
  // TODO(chrisha): We could walk the operands and follow references
  //     explicitly. If any of them are of reference type and there's no
  //     matching reference, this would be cause to blow up and die (we
  //     should get all of these as relocs and/or fixups).

  IntermediateReferenceMap::const_iterator ref_it =
      references_.upper_bound(instr_start);
  IntermediateReferenceMap::const_iterator ref_end =
      references_.lower_bound(instr_end);

  for (; ref_it != ref_end; ++ref_it) {
    BlockGraph::Block* ref_block = image_->GetContainingBlock(
        ref_it->second.base, 1);
    DCHECK(ref_block != NULL);

    // This is an inter-block reference.
    if (ref_block != current_block_) {
      // There should be no cross-block references to the middle of other
      // code blocks (to the top is fine, as we could be passing around a
      // function pointer). The exception is if the remote block is not
      // generated by cl.exe. In this case, there could be arbitrary labels
      // that act like functions within the body of that block, and referring
      // to them is perfectly fine.
      bool ref_attr_safe = true;
      if (ref_block->type() == BlockGraph::CODE_BLOCK) {
        ref_attr_safe =
            PETransformPolicy::CodeBlockAttributesAreBasicBlockSafe(ref_block,
                                                                    false);
      }
      if (ref_block->type() == BlockGraph::CODE_BLOCK &&
          ref_it->second.base != ref_block->addr() &&
          ref_attr_safe) {
        LOG_ERROR_OR_VLOG1(be_strict_with_current_block_)
            << "Found a non-control-flow code-block to middle-of-code-block "
            << "reference from block \"" << current_block_->name()
            << "\" to block \"" << ref_block->name() << "\".";
        return AbortOrTerminateDisassembly(be_strict_with_current_block_);
      }
    } else {
      // This is an intra-block reference.
      BlockGraph::Offset ref_offset =
          ref_it->second.base - current_block_->addr();

      // If this is to offset zero, we assume we are taking a pointer to
      // ourself, which is safe.
      if (ref_offset != 0) {
        // If this is 'clean' code it should be to data, and there should be a
        // label.
        BlockGraph::Label label;
        if (!current_block_->GetLabel(ref_offset, &label)) {
          LOG_ERROR_OR_VLOG1(be_strict_with_current_block_)
              << "Found an intra-block data-reference with no label.";
          return AbortOrTerminateDisassembly(be_strict_with_current_block_);
        } else {
          if (!label.has_attributes(BlockGraph::DATA_LABEL) ||
              label.has_attributes(BlockGraph::CODE_LABEL)) {
            LOG_ERROR_OR_VLOG1(be_strict_with_current_block_)
                << "Found an intra-block data-like reference to a non-data "
                << "or code label in block \"" << current_block_->name()
                << "\".";
            return AbortOrTerminateDisassembly(be_strict_with_current_block_);
          }
        }
      }
    }
  }

  return Disassembler::kDirectiveContinue;
}

CallbackDirective OldDecomposer::VisitPcRelativeFlowControlInstruction(
    AbsoluteAddress instr_abs,
    RelativeAddress instr_rel,
    const _DInst& instruction,
    bool end_of_code) {
  int fc = META_GET_FC(instruction.meta);
  DCHECK(fc == FC_UNC_BRANCH || fc == FC_CALL || fc == FC_CND_BRANCH);
  DCHECK_EQ(O_PC, instruction.ops[0].type);
  DCHECK_EQ(O_NONE, instruction.ops[1].type);
  DCHECK_EQ(O_NONE, instruction.ops[2].type);
  DCHECK_EQ(O_NONE, instruction.ops[3].type);
  DCHECK(instruction.ops[0].size == 8 ||
      instruction.ops[0].size == 16 ||
      instruction.ops[0].size == 32);
  // Distorm gives us size in bits, we want bytes.
  BlockGraph::Size size = instruction.ops[0].size / 8;

  // Get the reference's address. Note we assume it's in the instruction's
  // tail end - I don't know of a case where a PC-relative offset in a branch
  // or call is not the very last thing in an x86 instruction.
  AbsoluteAddress abs_src = instr_abs + instruction.size - size;
  AbsoluteAddress abs_dst = instr_abs + instruction.size +
      static_cast<size_t>(instruction.imm.addr);

  RelativeAddress src, dst;
  if (!image_file_.Translate(abs_src, &src) ||
      !image_file_.Translate(abs_dst, &dst)) {
    LOG(ERROR) << "Unable to translate absolute to relative addresses.";
    return Disassembler::kDirectiveAbort;
  }

  // Get the block associated with the destination address. It must exist
  // and be a code block.
  BlockGraph::Block* block = image_->GetContainingBlock(dst, 1);
  DCHECK(block != NULL);
  DCHECK_EQ(BlockGraph::CODE_BLOCK, block->type());

  // For short references, we should not see a fixup.
  ValidateOrAddReferenceMode mode = FIXUP_MUST_NOT_EXIST;
  if (size == kPointerSize) {
    // Long PC_RELATIVE reference within a single block? FIXUPs aren't
    // strictly necessary.
    if (block->Contains(src, kPointerSize))
      mode = FIXUP_MAY_EXIST;
    else
      // But if they're between blocks (section contributions), we expect to
      // find them.
      mode = FIXUP_MUST_EXIST;
  } else {
    // Since we slice by section contributions we no longer see short
    // references across blocks. If we do, bail!
    if (block != current_block_) {
      LOG(ERROR) << "Found a short PC-relative reference out of block \""
                 << current_block_->name() << "\".";
      return Disassembler::kDirectiveAbort;
    }
  }

  // Validate or create the reference, as necessary.
  if (!ValidateOrAddReference(mode, src, BlockGraph::PC_RELATIVE_REF, size,
                              dst, 0, &fixup_map_, &references_)) {
    LOG(ERROR) << "Failed to validate/create reference originating from "
               << "block \"" << current_block_->name() << "\".";
    return Disassembler::kDirectiveAbort;
  }

  // If this is a call and the destination is a non-returning function,
  // then indicate that we should terminate this disassembly path.
  if (fc == FC_CALL &&
      (block->attributes() & BlockGraph::NON_RETURN_FUNCTION)) {
    // TODO(chrisha): For now, we enforce that the call be to the beginning
    //    of the function. This may not be necessary, but better safe than
    //    sorry for now.
    if (block->addr() != dst) {
      LOG(ERROR) << "Calling inside the body of a non-returning function: "
                 << block->name();
      return Disassembler::kDirectiveAbort;
    }

    return Disassembler::kDirectiveTerminatePath;
  }

  // If we get here, then we don't think it's a non-returning call. If it's
  // not an unconditional jump and we're at the end of the code for this block
  // then we consider this as disassembling past the end.
  if (fc != FC_UNC_BRANCH && end_of_code)
    MarkDisassembledPastEnd();

  return Disassembler::kDirectiveContinue;
}

CallbackDirective OldDecomposer::VisitIndirectMemoryCallInstruction(
      const _DInst& instruction, bool end_of_code) {
  DCHECK_EQ(FC_CALL, META_GET_FC(instruction.meta));
  DCHECK_EQ(O_DISP, instruction.ops[0].type);

  // TODO(rogerm): Consider changing to image_file_.AbsToRelDisplacement()
  //     instead of translate. In theory, the indexing into a function-table
  //     could be statically offset such that the displacement falls outside
  //     of the image's address space. But, we have never seen the compiler
  //     generate code like that. This is left to use Translate, which will
  //     trigger an error in such a case.
  AbsoluteAddress disp_addr_abs(static_cast<uint32>(instruction.disp));
  RelativeAddress disp_addr_rel;
  if (!image_file_.Translate(disp_addr_abs, &disp_addr_rel)) {
    LOG(ERROR) << "Unable to translate call address.";
    return Disassembler::kDirectiveAbort;
  }

  // Try to dereference the address of the call instruction. This can fail
  // for blocks that are only initialized at runtime, so we don't fail if
  // we don't find a reference.
  IntermediateReferenceMap::const_iterator ref_it =
      references_.find(disp_addr_rel);
  if (ref_it == references_.end())
    return Disassembler::kDirectiveContinue;

  // NOTE: This process derails for bound import tables. In this case the
  //     attempted dereference above will fail, but we could still actually
  //     find the import name thunk by inspecting the offset of the memory
  //     location.

  // The reference must be direct and 32-bit.
  const IntermediateReference& ref = ref_it->second;
  DCHECK_EQ(BlockGraph::Reference::kMaximumSize, ref.size);
  DCHECK_EQ(0, ref.offset);

  // Look up the thunk this refers to.
  BlockGraph::Block* thunk = image_->GetBlockByAddress(ref.base);
  if (thunk == NULL) {
    LOG(ERROR) << "Unable to dereference intermediate reference at "
               << disp_addr_rel << " to " << ref.base << ".";
    return Disassembler::kDirectiveAbort;
  }

  if (ref.type == BlockGraph::RELATIVE_REF) {
    // If this is a relative reference it must be part of an import address
    // table (during runtime this address would be patched up with an absolute
    // reference). Thus we expect the referenced block to be data, an import
    // name thunk.
    DCHECK_EQ(BlockGraph::DATA_BLOCK, thunk->type());
  } else {
    // If this is an absolute address it should actually point directly to
    // code.
    DCHECK_EQ(BlockGraph::ABSOLUTE_REF, ref.type);
    DCHECK_EQ(BlockGraph::CODE_BLOCK, thunk->type());
  }

  // Either way, if the block is non-returning we terminate this path of
  // disassembly.
  if ((thunk->attributes() & BlockGraph::NON_RETURN_FUNCTION) != 0)
    return Disassembler::kDirectiveTerminatePath;

  if (end_of_code)
    MarkDisassembledPastEnd();

  return Disassembler::kDirectiveContinue;
}

CallbackDirective OldDecomposer::OnInstruction(const Disassembler& walker,
                                            const _DInst& instruction) {
  // Get the relative address of this instruction.
  AbsoluteAddress instr_abs(static_cast<uint32>(instruction.addr));
  RelativeAddress instr_rel;
  if (!image_file_.Translate(instr_abs, &instr_rel)) {
    LOG(ERROR) << "Unable to translate instruction address.";
    return Disassembler::kDirectiveAbort;
  }
  RelativeAddress after_instr_rel = instr_rel + instruction.size;

#ifndef NDEBUG
  // If we're in debug mode, it's helpful to have a pointer directly to the
  // beginning of this instruction in memory.
  BlockGraph::Offset instr_offset = instr_rel - current_block_->addr();
  const uint8* instr_data = current_block_->data() + instr_offset;
#endif

  // TODO(chrisha): Certain instructions require aligned data (ie: MMX/SSE
  //     instructions). We need to follow the data that these instructions
  //     refer to, and set their alignment appropriately. For now, alignment
  //     is simply preserved from the original image.

  CallbackDirective directive = LookPastInstructionForData(after_instr_rel);
  if (IsFatalCallbackDirective(directive))
    return directive;

  // We're at the end of code in this block if we encountered data, or this is
  // the last instruction to be processed.
  RelativeAddress block_end(current_block_->addr() + current_block_->size());
  bool end_of_code = (directive == Disassembler::kDirectiveTerminatePath) ||
      (after_instr_rel >= block_end);

  int fc = META_GET_FC(instruction.meta);

  if (fc == FC_NONE) {
    // There's no control flow and we're at the end of the block. Mark the
    // block as dirty.
    if (end_of_code)
      MarkDisassembledPastEnd();

    return CombineCallbackDirectives(directive,
        VisitNonFlowControlInstruction(instr_rel, after_instr_rel));
  }

  if ((fc == FC_UNC_BRANCH || fc == FC_CALL || fc == FC_CND_BRANCH) &&
      instruction.ops[0].type == O_PC) {
    // For all branches, calls and conditional branches to PC-relative
    // addresses, record a PC-relative reference.
    return CombineCallbackDirectives(directive,
        VisitPcRelativeFlowControlInstruction(instr_abs,
                                              instr_rel,
                                              instruction,
                                              end_of_code));
  }

  // We explicitly handle indirect memory call instructions. These can often
  // be tracked down as pointing to a block in this image, or to an import
  // name thunk from another module.
  if (fc == FC_CALL && instruction.ops[0].type == O_DISP) {
    return CombineCallbackDirectives(directive,
        VisitIndirectMemoryCallInstruction(instruction, end_of_code));
  }

  // Look out for blocks where disassembly seems to run off the end of the
  // block. We do not treat interrupts as flow control as execution can
  // continue past the interrupt.
  if (fc != FC_RET && fc != FC_UNC_BRANCH && end_of_code)
    MarkDisassembledPastEnd();

  return directive;
}

bool OldDecomposer::CreatePEImageBlocksAndReferences(
    PEFileParser::PEHeader* header) {
  PEFileParser::AddReferenceCallback add_reference(
      base::Bind(&OldDecomposer::AddReferenceCallback,
                 base::Unretained(this)));
  PEFileParser parser(image_file_, image_, add_reference);
  parser.set_on_import_thunk(
      base::Bind(&OldDecomposer::OnImportThunkCallback,
                 base::Unretained(this)));

  if (!parser.ParseImage(header)) {
    LOG(ERROR) << "Unable to parse PE image.";
    return false;
  }

  return true;
}

bool OldDecomposer::FinalizeIntermediateReferences() {
  IntermediateReferenceMap::const_iterator it(references_.begin());
  IntermediateReferenceMap::const_iterator end(references_.end());

  for (; it != end; ++it) {
    RelativeAddress src_addr(it->first);
    BlockGraph::Block* src = image_->GetBlockByAddress(src_addr);
    RelativeAddress dst_base_addr(it->second.base);
    RelativeAddress dst_addr(dst_base_addr + it->second.offset);
    BlockGraph::Block* dst = image_->GetBlockByAddress(dst_base_addr);

    if (src == NULL || dst == NULL) {
      LOG(ERROR) << "Reference source or base destination address is out of "
                 << "range, src: " << src << ", dst: " << dst;
      return false;
    }

    RelativeAddress src_start = src->addr();
    RelativeAddress dst_start = dst->addr();

    // Get the offset of the ultimate destination relative to the start of the
    // destination block.
    BlockGraph::Offset dst_offset = dst_addr - dst_start;

    // Get the offset of the actual referenced object relative to the start of
    // the destination block.
    BlockGraph::Offset dst_base = dst_base_addr - dst_start;

    BlockGraph::Reference ref(it->second.type,
                              it->second.size,
                              dst,
                              dst_offset,
                              dst_base);
    src->SetReference(src_addr - src_start, ref);
  }

  references_.clear();

  return true;
}

bool OldDecomposer::ConfirmFixupsVisited() const {
  bool success = true;

  // Ideally, all fixups should have been visited during decomposition.
  // TODO(chrisha): Address the root problems underlying the following
  //     temporary fix.
  FixupMap::const_iterator fixup_it = fixup_map_.begin();
  for (; fixup_it != fixup_map_.end(); ++fixup_it) {
    if (fixup_it->second.visited)
      continue;

    const BlockGraph::Block* block =
        image_->GetContainingBlock(fixup_it->first, kPointerSize);
    DCHECK(block != NULL);

    // We know that we currently do not have full disassembly coverage as there
    // are several orphaned pieces of apparently unreachable code in the CRT
    // that we do not disassemble, but which may contain jmp or call commands.
    // Thus, we expect that missed fixups are all PC-relative and lie within
    // code blocks.
    if (block->type() == BlockGraph::CODE_BLOCK &&
        fixup_it->second.type == BlockGraph::PC_RELATIVE_REF)
      continue;

    success = false;
    LOG(ERROR) << "Unexpected unseen fixup at " << fixup_it->second.location;
  }

  return success;
}

bool OldDecomposer::FindPaddingBlocks() {
  DCHECK(image_ != NULL);
  DCHECK(image_->graph() != NULL);

  BlockGraph::BlockMap::iterator block_it =
      image_->graph()->blocks_mutable().begin();
  for (; block_it != image_->graph()->blocks_mutable().end(); ++block_it) {
    BlockGraph::Block& block = block_it->second;

    // Padding blocks must not have any symbol information: no labels,
    // no references, no referrers, and they must be a gap block.
    if (block.labels().size() != 0 ||
        block.references().size() != 0 ||
        block.referrers().size() != 0 ||
        (block.attributes() & BlockGraph::GAP_BLOCK) == 0)
      continue;

    switch (block.type()) {
      // Code blocks should be fully defined and consist of only int3s.
      case BlockGraph::CODE_BLOCK: {
        if (block.data_size() != block.size() ||
            RepeatedValue(block.data(), block.data_size()) != kInt3)
          continue;
        break;
      }

      // Data blocks should be uninitialized or have fully defined data
      // consisting only of zeros.
      default: {
        DCHECK_EQ(BlockGraph::DATA_BLOCK, block.type());
        if (block.data_size() == 0)  // Uninitialized data blocks are padding.
          break;
        if (block.data_size() != block.size() ||
            RepeatedValue(block.data(), block.data_size()) != 0)
          continue;
      }
    }

    // If we fall through to this point, then the block is a padding block.
    block.set_attribute(BlockGraph::PADDING_BLOCK);
  }

  return true;
}

bool OldDecomposer::CreateSections() {
  // Iterate through the image sections, and create sections in the BlockGraph.
  size_t num_sections = image_file_.nt_headers()->FileHeader.NumberOfSections;
  for (size_t i = 0; i < num_sections; ++i) {
    const IMAGE_SECTION_HEADER* header = image_file_.section_header(i);
    std::string name = pe::PEFile::GetSectionName(*header);
    BlockGraph::Section* section = image_->graph()->AddSection(
        name, header->Characteristics);
    DCHECK(section != NULL);

    // For now, we expect them to have been created with the same IDs as those
    // in the original image.
    if (section->id() != i) {
      LOG(ERROR) << "Unexpected section ID.";
      return false;
    }
  }

  return true;
}

bool OldDecomposer::LoadDebugStreams(IDiaSession* dia_session) {
  DCHECK(dia_session != NULL);

  // Load the fixups. These must exist.
  PdbFixups pdb_fixups;
  SearchResult search_result = FindAndLoadDiaDebugStreamByName(
      kFixupDiaDebugStreamName, dia_session, &pdb_fixups);
  if (search_result != kSearchSucceeded) {
    if (search_result == kSearchFailed) {
      LOG(ERROR) << "PDB file does not contain a FIXUP stream. Module must be "
                    "linked with '/PROFILE' or '/DEBUGINFO:FIXUP' flag.";
    }
    return false;
  }

  // Load the omap_from table. It is not necessary that one exist.
  std::vector<OMAP> omap_from;
  search_result = FindAndLoadDiaDebugStreamByName(
      kOmapFromDiaDebugStreamName, dia_session, &omap_from);
  if (search_result == kSearchErrored)
    return false;

  // Translate and validate fixups.
  if (!OmapAndValidateFixups(omap_from, pdb_fixups))
    return false;

  return true;
}

bool OldDecomposer::OmapAndValidateFixups(const std::vector<OMAP>& omap_from,
                                       const PdbFixups& pdb_fixups) {
  bool have_omap = omap_from.size() != 0;

  // The resource section in Chrome is modified post-link by a tool that adds a
  // manifest to it. This causes all of the fixups in the resource section (and
  // anything beyond it) to be invalid. As long as the resource section is the
  // last section in the image, this is not a problem (we can safely ignore the
  // .rsrc fixups, which we know how to parse without them). However, if there
  // is a section after the resource section, things will have been shifted
  // and potentially crucial fixups will be invalid.
  RelativeAddress rsrc_start(0xffffffff), max_start;
  size_t num_sections = image_file_.nt_headers()->FileHeader.NumberOfSections;
  for (size_t i = 0; i < num_sections; ++i) {
    const IMAGE_SECTION_HEADER* header = image_file_.section_header(i);
    RelativeAddress start(header->VirtualAddress);
    if (start > max_start)
      max_start = start;
    if (strncmp(kResourceSectionName,
                reinterpret_cast<const char*>(header->Name),
                IMAGE_SIZEOF_SHORT_NAME) == 0) {
      rsrc_start = start;
      break;
    }
  }

  // Ensure there are no sections after the resource section.
  if (max_start > rsrc_start) {
    LOG(ERROR) << kResourceSectionName << " section is not the last section.";
    return false;
  }

  // Ensure the fixups are all valid, and populate the fixup map.
  for (size_t i = 0; i < pdb_fixups.size(); ++i) {
    if (!pdb_fixups[i].ValidHeader()) {
      LOG(ERROR) << "Unknown fixup header: "
                 << base::StringPrintf("0x%08X.", pdb_fixups[i].header);
      return false;
    }

    // For now, we skip any offset fixups. We've only seen this in the context
    // of TLS data access, and we don't mess with TLS structures.
    if (pdb_fixups[i].is_offset())
      continue;

    // All fixups we handle should be full size pointers.
    DCHECK_EQ(kPointerSize, pdb_fixups[i].size());

    // Get the original addresses, and map them through OMAP information.
    // Normally DIA takes care of this for us, but there is no API for
    // getting DIA to give us FIXUP information, so we have to do it manually.
    RelativeAddress rva_location(pdb_fixups[i].rva_location);
    RelativeAddress rva_base(pdb_fixups[i].rva_base);
    if (have_omap) {
      rva_location = pdb::TranslateAddressViaOmap(omap_from, rva_location);
      rva_base = pdb::TranslateAddressViaOmap(omap_from, rva_base);
    }

    // If these are part of the .rsrc section, ignore them.
    if (rva_location >= rsrc_start)
      continue;

    // Ensure they live within the image, and refer to things within the
    // image.
    if (!image_file_.Contains(rva_location, kPointerSize) ||
        !image_file_.Contains(rva_base, 1)) {
      LOG(ERROR) << "Fixup refers to addresses outside of image.";
      return false;
    }

    // Add the fix up, and ensure the source address is unique.
    Fixup fixup = { PdbFixupTypeToReferenceType(pdb_fixups[i].type),
                    pdb_fixups[i].refers_to_code(),
                    pdb_fixups[i].is_data(),
                    false,
                    rva_location,
                    rva_base };
    bool added = fixup_map_.insert(std::make_pair(rva_location, fixup)).second;
    if (!added) {
      LOG(ERROR) << "Colliding fixups at " << rva_location;
      return false;
    }
  }

  return true;
}

bool OldDecomposer::RegisterStaticInitializerPatterns(
    const base::StringPiece& begin, const base::StringPiece& end) {
  // Ensuring the patterns each have exactly one capturing group.
  REPair re_pair = std::make_pair(RE(begin.as_string()),
                                  RE(end.as_string()));
  if (re_pair.first.NumberOfCapturingGroups() != 1 ||
      re_pair.second.NumberOfCapturingGroups() != 1)
    return false;

  static_initializer_patterns_.push_back(re_pair);

  return true;
}

bool OldDecomposer::RegisterNonReturningFunction(
    const base::StringPiece& function_name) {
  return non_returning_functions_.insert(function_name.as_string()).second;
}

bool OldDecomposer::RegisterNonReturningImport(
    const base::StringPiece& module_name,
    const base::StringPiece& function_name) {
  StringSet& module_set = non_returning_imports_[module_name.as_string()];
  return module_set.insert(function_name.as_string()).second;
}

bool OldDecomposer::LoadBlockGraphFromPdbStream(const PEFile& image_file,
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

bool OldDecomposer::LoadBlockGraphFromPdb(const base::FilePath& pdb_path,
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
  scoped_refptr<pdb::PdbStream> block_graph_stream =
      GetBlockGraphStreamFromPdb(&pdb_file);
  if (block_graph_stream.get() == NULL) {
    *stream_exists = false;
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

scoped_refptr<pdb::PdbStream> OldDecomposer::GetBlockGraphStreamFromPdb(
    pdb::PdbFile* pdb_file) {
  scoped_refptr<pdb::PdbStream> block_graph_stream;
  // Get the PDB header and try to get the block-graph ID stream from it.
  pdb::PdbInfoHeader70 pdb_header = {0};
  pdb::NameStreamMap name_stream_map;
  if (!ReadHeaderInfoStream(pdb_file->GetStream(pdb::kPdbHeaderInfoStream),
                           &pdb_header,
                           &name_stream_map)) {
    LOG(ERROR) << "Failed to read header info stream.";
    return block_graph_stream;
  }
  pdb::NameStreamMap::const_iterator name_it = name_stream_map.find(
      pdb::kSyzygyBlockGraphStreamName);
  if (name_it == name_stream_map.end()) {
    return block_graph_stream;
  }

  // Get the block-graph stream and ensure that it's not empty.
  block_graph_stream = pdb_file->GetStream(name_it->second);
  if (block_graph_stream.get() == NULL) {
    LOG(ERROR) << "Failed to read the block-graph stream from the PDB.";
    return block_graph_stream;
  }
  if (block_graph_stream->length() == 0) {
    LOG(ERROR) << "The block-graph stream is empty.";
    return block_graph_stream;
  }

  return block_graph_stream;
}

bool OldDecomposer::OnImportThunkCallback(const char* module_name,
                                       const char* symbol_name,
                                       BlockGraph::Block* thunk) {
  DCHECK(module_name != NULL);
  DCHECK(symbol_name != NULL);
  DCHECK(thunk != NULL);

  // Look for the module first.
  StringSetMap::const_iterator module_it =
      non_returning_imports_.find(std::string(module_name));
  if (module_it == non_returning_imports_.end())
    return true;

  // Look for the symbol within the module.
  if (module_it->second.count(std::string(symbol_name)) == 0)
    return true;

  // If we get here then the imported symbol is found. Decorate the thunk.
  thunk->set_attribute(BlockGraph::NON_RETURN_FUNCTION);
  VLOG(1) << "Forcing non-returning attribute on imported symbol \""
          << symbol_name << "\" from module \"" << module_name << "\".";

  return true;
}

}  // namespace pe

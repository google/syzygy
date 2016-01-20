// Copyright 2015 Google Inc. All Rights Reserved.
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

#include "syzygy/refinery/analyzers/analyzer_util.h"

#include "base/logging.h"
#include "syzygy/refinery/process_state/refinery.pb.h"

namespace refinery {

void ParseContext(const CONTEXT& ctx, RegisterInformation* register_info) {
  DCHECK(register_info != nullptr);
  if (ctx.ContextFlags & CONTEXT_SEGMENTS) {
    register_info->set_seg_gs(ctx.SegGs);
    register_info->set_seg_fs(ctx.SegFs);
    register_info->set_seg_es(ctx.SegEs);
    register_info->set_seg_ds(ctx.SegDs);
  }
  if (ctx.ContextFlags & CONTEXT_INTEGER) {
    register_info->set_edi(ctx.Edi);
    register_info->set_esi(ctx.Esi);
    register_info->set_ebx(ctx.Ebx);
    register_info->set_edx(ctx.Edx);
    register_info->set_ecx(ctx.Ecx);
    register_info->set_eax(ctx.Eax);
  }
  if (ctx.ContextFlags & CONTEXT_CONTROL) {
    register_info->set_ebp(ctx.Ebp);
    register_info->set_eip(ctx.Eip);
    register_info->set_seg_cs(ctx.SegCs);
    register_info->set_eflags(ctx.EFlags);
    register_info->set_esp(ctx.Esp);
    register_info->set_seg_ss(ctx.SegSs);
  }
}

SimpleProcessAnalysis::SimpleProcessAnalysis(ProcessState* process_state)
    : process_state_(process_state) {
}
SimpleProcessAnalysis::SimpleProcessAnalysis(
    ProcessState* process_state,
    scoped_refptr<DiaSymbolProvider> dia_symbol_provider,
    scoped_refptr<SymbolProvider> symbol_provider)
    : process_state_(process_state),
      dia_symbol_provider_(dia_symbol_provider),
      symbol_provider_(symbol_provider) {
}

ProcessState* SimpleProcessAnalysis::process_state() const {
  return process_state_;
}

scoped_refptr<DiaSymbolProvider> SimpleProcessAnalysis::dia_symbol_provider()
    const {
  // TODO(siggi): Should there be a non-null assert here?
  return dia_symbol_provider_;
}

scoped_refptr<SymbolProvider> SimpleProcessAnalysis::symbol_provider() const {
  // TODO(siggi): Should there be a non-null assert here?
  return symbol_provider_;
}

}  // namespace refinery

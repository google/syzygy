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

#ifndef SYZYGY_REFINERY_ANALYZERS_ANALYZER_UTIL_H_
#define SYZYGY_REFINERY_ANALYZERS_ANALYZER_UTIL_H_

#include <windows.h>
#include <winnt.h>

#include "syzygy/refinery/analyzers/analyzer.h"

namespace refinery {

// fwd.
class RegisterInformation;

void ParseContext(const CONTEXT& ctx, RegisterInformation* register_info);

// Provides the simplest possible implementation of the ProcessAnalysis
// interface by storing ProcessState et al in member variables.
class SimpleProcessAnalysis : public Analyzer::ProcessAnalysis {
 public:
  // Creates an instance with null symbol providers.
  explicit SimpleProcessAnalysis(ProcessState* process_state);
  SimpleProcessAnalysis(ProcessState* process_state,
                        scoped_refptr<DiaSymbolProvider> dia_symbol_provider,
                        scoped_refptr<SymbolProvider> symbol_provider);

  // @name ProcessAnalysis implementation.
  // @{
  ProcessState* process_state() const override;
  scoped_refptr<DiaSymbolProvider> dia_symbol_provider() const override;
  scoped_refptr<SymbolProvider> symbol_provider() const override;
  // @}

  void set_process_state(ProcessState* process_state) {
    process_state_ = process_state;
  }
  void set_dia_symbol_provider(
      scoped_refptr<DiaSymbolProvider> dia_symbol_provider) {
    dia_symbol_provider_ = dia_symbol_provider;
  }
  void set_symbol_provider(scoped_refptr<SymbolProvider> symbol_provider) {
    symbol_provider_ = symbol_provider;
  }

 private:
  // Not owned - the process state must outlive this instance.
  ProcessState* process_state_;
  scoped_refptr<DiaSymbolProvider> dia_symbol_provider_;
  scoped_refptr<SymbolProvider> symbol_provider_;
};

}  // namespace refinery

#endif  // SYZYGY_REFINERY_ANALYZERS_ANALYZER_UTIL_H_

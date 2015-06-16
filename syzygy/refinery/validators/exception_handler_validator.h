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

#ifndef SYZYGY_REFINERY_VALIDATORS_EXCEPTION_HANDLER_VALIDATOR_H_
#define SYZYGY_REFINERY_VALIDATORS_EXCEPTION_HANDLER_VALIDATOR_H_

#include "base/macros.h"
#include "syzygy/refinery/validators/validator.h"

namespace refinery {

// A validator for a thread's exception handler chain. This implementation
// relies on the presence of the TEB to provide the first handler (this is the
// case for dumps captured with MiniDumpWithProcessThreadData).
// TODO(manzagop): move the extraction of the exception chain to an analyzer.
// TODO(manzagop): validate exception handlers are in the image's allowed set.
class ExceptionHandlerValidator : public Validator {
 public:
  ExceptionHandlerValidator() {}

  ValidationResult Validate(ProcessState* process_state,
                            ValidationReport* report) override;

 private:
  DISALLOW_COPY_AND_ASSIGN(ExceptionHandlerValidator);
};

}  // namespace refinery

#endif  // SYZYGY_REFINERY_VALIDATORS_EXCEPTION_HANDLER_VALIDATOR_H_

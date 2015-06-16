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

#ifndef SYZYGY_REFINERY_VALIDATORS_VALIDATOR_H_
#define SYZYGY_REFINERY_VALIDATORS_VALIDATOR_H_

#include "syzygy/refinery/process_state/process_state.h"

namespace refinery {

// Fwd
class ValidationReport;

// The interface implemented by validators. Each validator processes the process
// state in search of expectation violations or inconsistencies, which are then
// added to the validation report.
class Validator {
 public:
  virtual ~Validator() = 0 {};

  enum ValidationResult {
    VALIDATION_COMPLETE,
    VALIDATION_ERROR,
  };

  // Validate @p process_state and update the validation @p report if necessary.
  // @param process_state the representation of a process.
  // @param report the validation report to suppplement with detected
  //    expectation violations or inconsistencies.
  // @returns a validation result. A validator should not be invoked again after
  //    it's returned VALIDATION_COMPLETE. If a validator returns
  //    VALIDATION_ERROR @p report may be inconsistent.
  virtual ValidationResult Validate(ProcessState* process_state,
                                    ValidationReport* report) = 0;
};

}  // namespace refinery

#endif  // SYZYGY_REFINERY_VALIDATORS_VALIDATOR_H_

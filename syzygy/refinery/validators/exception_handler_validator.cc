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

#include "syzygy/refinery/validators/exception_handler_validator.h"

#include <string>
#include <vector>

#include "base/strings/stringprintf.h"
#include "syzygy/refinery/core/address.h"
#include "syzygy/refinery/core/addressed_data.h"
#include "syzygy/refinery/process_state/process_state_util.h"
#include "syzygy/refinery/process_state/refinery.pb.h"

namespace refinery {
namespace {

bool GetTib(StackRecordPtr stack,
            BytesLayerPtr bytes_layer,
            NT_TIB* tib) {
  // Determine the TIB's address.
  const Stack& stack_proto = stack->data();
  if (!stack_proto.has_thread_info() ||
      !stack_proto.thread_info().has_teb_address()) {
    return false;
  }
  const Address tib_address = stack_proto.thread_info().teb_address();

  // Get the bytes backing the TIB.
  const AddressRange tib_range(tib_address, sizeof(tib));
  std::vector<BytesRecordPtr> matching_records;
  bytes_layer->GetRecordsSpanning(tib_range, &matching_records);
  if (matching_records.size() != 1)
    return false;
  BytesRecordPtr bytes_record = matching_records[0];

  // Get the TIB.
  const Bytes& bytes = bytes_record->data();
  AddressedData addressed_data(bytes_record->range(), bytes.data().c_str());
  return addressed_data.GetAt(tib_address, tib);
}

bool GetExceptionRegistrationRecord(
    AddressRange record_range,
    BytesLayerPtr bytes_layer,
    EXCEPTION_REGISTRATION_RECORD* record) {
  DCHECK(record_range.IsValid());

  // Get backing bytes.
  std::vector<BytesRecordPtr> matching_records;
  bytes_layer->GetRecordsSpanning(record_range, &matching_records);
  if (matching_records.size() != 1)
    return false;
  BytesRecordPtr bytes_record = matching_records[0];

  // Get the record.
  const Bytes& bytes = bytes_record->data();
  AddressedData addressed_data(bytes_record->range(), bytes.data().c_str());
  return addressed_data.GetAt(record_range.start(), record);
}

void AddViolation(ValidationReport* report,
                  ViolationType type,
                  const std::string& description) {
  Violation* violation = report->add_error();
  violation->set_type(type);
  violation->set_description(description);
}

void AddNoChainViolation(StackRecordPtr stack, ValidationReport* report) {
  const uint32_t thread_id = stack->data().thread_info().thread_id();
  std::string description = base::StringPrintf(
      "Thread %d has no exception registration record.", thread_id);
  AddViolation(report, VIOLATION_NO_EXCEPTION_REGISTRATION_RECORD, description);
}

void AddChainOutsideStackViolation(Address record_address,
                                   StackRecordPtr stack,
                                   ValidationReport* report) {
  const uint32_t thread_id = stack->data().thread_info().thread_id();
  std::string description = base::StringPrintf(
      "Exception registration record not in stack (thread %d, record at %lld)",
      thread_id, record_address);
  AddViolation(report, VIOLATION_EXCEPTION_REGISTRATION_RECORD_NOT_IN_STACK,
               description);
}

void AddChainAddressDecreaseViolation(Address record_addr,
                                      Address next_addr,
                                      StackRecordPtr stack,
                                      ValidationReport* report) {
  const uint32_t thread_id = stack->data().thread_info().thread_id();
  std::string description = base::StringPrintf(
      "Exception chain address decrease (thread %d: record at %lld points to "
      "%lld).",
      thread_id, record_addr, next_addr);
  AddViolation(report, VIOLATION_EXCEPTION_CHAIN_ADDRESS_DECREASE, description);
}

}  // namespace

Validator::ValidationResult ExceptionHandlerValidator::Validate(
    ProcessState* process_state,
    ValidationReport* report) {
  DCHECK(process_state); DCHECK(report);

  BytesLayerPtr bytes_layer;
  if (!process_state->FindLayer(&bytes_layer))
    return VALIDATION_ERROR;
  StackLayerPtr stack_layer;
  if (!process_state->FindLayer(&stack_layer))
    return VALIDATION_ERROR;

  for (StackRecordPtr stack : *stack_layer) {
    // Get the TIB.
    // TODO(manzagop): stop assuming 32bit-ness for the minidump. Instead
    // implement type detection, eg by looking at the ntll module, and
    // requesting its NT_TIB.
    NT_TIB tib = {};
    if (!GetTib(stack, bytes_layer, &tib))
      return VALIDATION_ERROR;

    // Validate there is at least one handler.
    Address record_address = reinterpret_cast<Address>(tib.ExceptionList);
    if (record_address == static_cast<Address>(-1))
      AddNoChainViolation(stack, report);

    // Walk the exception registration record chain
    // TODO(manzagop): defend against an infinite loop.
    while (record_address != static_cast<Address>(-1)) {
      // Ensure the exception registration record is in stack.
      AddressRange record_range(record_address,
                                sizeof(EXCEPTION_REGISTRATION_RECORD));
      if (!stack->range().Contains(record_range)) {
        AddChainOutsideStackViolation(record_address, stack, report);
        break;  // Stop processing the chain.
      }

      // Get the record. Failing to obtain it is an error, as the stack is
      // assumed present, and we've validated the record is in stack.
      EXCEPTION_REGISTRATION_RECORD record = {};
      if (!GetExceptionRegistrationRecord(record_range, bytes_layer, &record))
        return VALIDATION_ERROR;

      // Validate the address of the next exception registration record.
      Address next_address = reinterpret_cast<Address>(record.Next);
      if (next_address < record_address) {
        AddChainAddressDecreaseViolation(record_address, next_address, stack,
                                         report);
        break;  // Stop processing the chain.
      }

      record_address = next_address;
    }
  }

  return VALIDATION_COMPLETE;
}

}  // namespace refinery

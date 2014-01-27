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
//
// Declares utility functions used by the call trace client and its unit
// tests.

#include "syzygy/trace/client/client_utils.h"

#include <psapi.h>

#include "base/environment.h"
#include "base/file_util.h"
#include "base/logging.h"
#include "base/string_number_conversions.h"
#include "base/utf_string_conversions.h"
#include "base/strings/string_split.h"
#include "base/win/pe_image.h"
#include "syzygy/common/com_utils.h"
#include "syzygy/common/path_util.h"
#include "syzygy/core/file_util.h"
#include "syzygy/trace/client/rpc_session.h"

// http://blogs.msdn.com/oldnewthing/archive/2004/10/25/247180.aspx
extern "C" IMAGE_DOS_HEADER __ImageBase;

namespace trace {
namespace client {

namespace {

// Loads the environment variable @p env_var and splits it at semi-colons. Each
// substring is treated as a comma-separated "path,value" pair, with the first
// substring being allowed to be a "value" singleton interpreted as a default
// value. Looks for the presence of @p module_path in the pairs, with more
// exact matches taking higher priority (highest is exact path matching,
// than basename matching and finally the default value).
//
// Returns true if a value has been found via the environment variable, false
// if no environment variable exists or no match was found. If no match is
// found @p value is left unmodified.
template<typename ReturnType, typename ConversionFunctor>
bool GetModuleValueFromEnvVar(const char* env_var_name,
                              const base::FilePath& module_path,
                              const ReturnType& default_value,
                              const ConversionFunctor& convert,
                              ReturnType* value) {
  size_t best_score = 0;
  ReturnType best_value = default_value;

  // Get the environment variable. If it's empty, we can return early.
  scoped_ptr<base::Environment> env(base::Environment::Create());
  std::string env_var;
  env->GetVar(env_var_name, &env_var);
  if (env_var.empty())
    return false;

  // Get the absolute path and the basename of the module. We will use these
  // for matching.
  base::FilePath abs_module_path(base::MakeAbsoluteFilePath(module_path));
  // TODO(chrisha): Is this wise? There's all kinds of environmental trouble
  //     that can lead to path normalization failing, and there is infact no
  //     guarantee that an arbitrary file path can be normalized given an
  //     arbitrary process' permissions.
  CHECK(!abs_module_path.empty());
  base::FilePath base_module_path = module_path.BaseName();

  std::vector<std::string> pairs;
  base::SplitString(env_var, ';', &pairs);

  for (size_t i = 0; i < pairs.size(); ++i) {
    if (pairs[i].empty())
      continue;

    std::vector<std::string> path_value;
    base::SplitString(pairs[i], ',', &path_value);

    size_t score = 0;

    // Ignore malformed fields.
    if (path_value.size() > 2)
      continue;

    // Ignore entries with improperly formatted values.
    ReturnType value = default_value;
    if (!convert(path_value.back(), &value))
      continue;

    if (path_value.size() == 1) {
      // This is a default value specified without a path.
      score = 1;
    } else if (path_value.size() == 2) {
      base::FilePath path(UTF8ToWide(path_value[0]));

      // Ignore improperly formatted paths.
      if (path.empty())
        continue;

      if (base_module_path == path) {
        // The basename of the module matches the path.
        score = 2;
      } else if (abs_module_path == path) {
        // The full path of the module matches.
        score = 3;
      } else {
        // Due to mounting files in different locations we can often get
        // differing but equivalent paths to the same file. Thus, we pull out
        // the big guns and do a file-system level comparison to see if they
        // do in fact refer to the same file.
        core::FilePathCompareResult result = core::CompareFilePaths(
            abs_module_path, path);
        if (result == core::kEquivalentFilePaths)
          score = 3;
      }
    }

    if (score > best_score) {
      best_score = score;
      best_value = value;
    }
  }

  if (best_score > 0) {
    *value = best_value;
    return true;
  }

  return false;
}

struct KeepAsString {
  bool operator()(const std::string& s1, std::string* s2) const {
    DCHECK(s2 != NULL);
    *s2 = s1;
    return true;
  }
};

struct ToInt {
  bool operator()(const std::string& s, int* i) const {
    DCHECK(i != NULL);
    if (!base::StringToInt(s, i))
      return false;
    return true;
  }
};

}  // namespace

int ReasonToEventType(DWORD reason) {
  switch (reason) {
    case DLL_PROCESS_ATTACH:
      return TRACE_PROCESS_ATTACH_EVENT;

    case DLL_PROCESS_DETACH:
      return TRACE_PROCESS_DETACH_EVENT;

    case DLL_THREAD_ATTACH:
      return TRACE_THREAD_ATTACH_EVENT;

    case DLL_THREAD_DETACH:
      return TRACE_THREAD_DETACH_EVENT;

    default:
      NOTREACHED() << "Invalid reason: " << reason << ".";
      return -1;
  }
}

RecordPrefix* GetRecordPrefix(void *record) {
  DCHECK(record != NULL);

  return reinterpret_cast<RecordPrefix*>(record) - 1;
}

TraceFileSegment::TraceFileSegment()
    : header(NULL),
      base_ptr(NULL),
      write_ptr(NULL),
      end_ptr(NULL) {
  // Zero the RPC buffer.
  memset(&buffer_info, 0, sizeof(buffer_info));
}

// Returns true if there's enough space left in the given segment to write
// num_bytes of raw data.
bool TraceFileSegment::CanAllocateRaw(size_t num_bytes) const {
  DCHECK(write_ptr != NULL);
  DCHECK(end_ptr != NULL);
  DCHECK(num_bytes != 0);
  return (write_ptr + num_bytes) <= end_ptr;
}

// Returns true if there's enough space left in the given segment to write
// a prefixed record of length num_bytes.
bool TraceFileSegment::CanAllocate(size_t num_bytes) const {
  DCHECK(num_bytes != 0);
  return CanAllocateRaw(num_bytes + sizeof(RecordPrefix));
}

void FillPrefix(RecordPrefix* prefix, int type, size_t size) {
  prefix->size = size;
  prefix->version.hi = TRACE_VERSION_HI;
  prefix->version.lo = TRACE_VERSION_LO;
  prefix->type = static_cast<uint16>(type);
  prefix->timestamp = trace::common::GetTsc();
}

// Writes the segment header at the top of a segment, updating the bytes
// consumed and initializing the segment header structures.
void TraceFileSegment::WriteSegmentHeader(SessionHandle session_handle) {
  DCHECK(header == NULL);
  DCHECK(write_ptr != NULL);
  DCHECK(CanAllocate(sizeof(TraceFileSegmentHeader)));

  // The trace record allocation will write the record prefix and update
  // the number of bytes consumed within the buffer.

  RecordPrefix* prefix = reinterpret_cast<RecordPrefix*>(write_ptr);
  FillPrefix(prefix,
             TraceFileSegmentHeader::kTypeId,
             sizeof(TraceFileSegmentHeader));

  header = reinterpret_cast<TraceFileSegmentHeader*>(prefix + 1);
  header->thread_id = ::GetCurrentThreadId();
  header->segment_length = 0;

  write_ptr = reinterpret_cast<uint8*>(header + 1);
}

void* TraceFileSegment::AllocateTraceRecordImpl(int record_type,
                                                size_t record_size) {
  DCHECK(header != NULL);
  DCHECK(write_ptr != NULL);
  DCHECK(record_size != 0);

  const size_t total_size = sizeof(RecordPrefix) + record_size;

  DCHECK(CanAllocateRaw(total_size));

  // Clear the memory we're about to allocate. If this thread gets killed
  // before it can finish updating the trace record we want the allocated
  // record to have a somewhat consistent state.
  ::memset(write_ptr, 0, total_size);

  RecordPrefix* prefix = reinterpret_cast<RecordPrefix*>(write_ptr);
  FillPrefix(prefix, record_type, record_size);

  write_ptr += total_size;
  header->segment_length += total_size;

  return prefix + 1;
}

bool GetModuleBaseAddress(void* address_in_module, void** module_base) {
  DCHECK(address_in_module != NULL);
  DCHECK(module_base != NULL);

  // Get the address of the module. We do this by querying for the allocation
  // that contains the address of the function we intercepted. This must lie
  // within the instrumented module, and be part of the single allocation in
  // which the image of the module lies. The base of the module will be the
  // base address of the allocation.
  MEMORY_BASIC_INFORMATION mem_info = {};
  if (::VirtualQuery(address_in_module, &mem_info, sizeof(mem_info)) == 0) {
    DWORD error = ::GetLastError();
    LOG(ERROR) << "VirtualQuery failed: " << ::common::LogWe(error) << ".";
    return false;
  }

  *module_base = mem_info.AllocationBase;

#ifndef NDEBUG
  base::win::PEImage image(*module_base);
  DCHECK(image.VerifyMagic());
#endif

  return true;
}

bool GetModulePath(void* module_base, base::FilePath* module_path) {
  DCHECK(module_base != NULL);
  DCHECK(module_path != NULL);

  wchar_t buffer[1024];
  if (::GetMappedFileName(::GetCurrentProcess(), module_base, buffer,
                          arraysize(buffer)) == 0) {
    DWORD error = ::GetLastError();
    LOG(ERROR) << "GetMappedFileName failed: " << ::common::LogWe(error) << ".";
    return false;
  }

  base::FilePath device_path(buffer);
  if (!::common::ConvertDevicePathToDrivePath(device_path, module_path))
    return false;

  return true;
}

std::string GetInstanceIdForModule(const base::FilePath& module_path) {
  std::string id;
  // We don't care if the search is successful or not.
  GetModuleValueFromEnvVar(::kSyzygyRpcInstanceIdEnvVar, module_path,
                           id, KeepAsString(), &id);
  return id;
}

std::string GetInstanceIdForThisModule() {
  base::FilePath module_path;
  CHECK(GetModulePath(&__ImageBase, &module_path));

  std::string instance_id = GetInstanceIdForModule(module_path);

  return instance_id;
}

bool IsRpcSessionMandatory(const base::FilePath& module_path) {
  int value = 0;
  if (!GetModuleValueFromEnvVar(kSyzygyRpcSessionMandatoryEnvVar, module_path,
                                value, ToInt(), &value)) {
    return false;
  }

  if (value == 0)
    return false;

  // Anything non-zero is treated as 'true'.
  return true;
}

bool IsRpcSessionMandatoryForThisModule() {
  base::FilePath module_path;
  CHECK(GetModulePath(&__ImageBase, &module_path));

  if (IsRpcSessionMandatory(module_path))
    return true;

  return false;
}

bool InitializeRpcSession(RpcSession* rpc_session, TraceFileSegment* segment) {
  DCHECK(rpc_session != NULL);

  std::string id = trace::client::GetInstanceIdForThisModule();
  rpc_session->set_instance_id(UTF8ToWide(id));
  if (rpc_session->CreateSession(segment))
    return true;

  // If the session is not mandatory then return and indicate that we failed
  // to initialize properly.
  if (!IsRpcSessionMandatoryForThisModule())
    return false;

  // If you're seeing this error message it's because the process was unable
  // to initialize an RPC session, and the state of the
  // SYZYGY_RPC_SESSION_MANDATORY environment variable indicated that it was
  // required. Make sure the call-trace service is running with the appropriate
  // instance ID!
  LOG(ERROR) << "RPC session is mandatory, but unable to be created.";

  // Dump some context regarding the decision to abort.
  base::FilePath module_path;
  if (GetModulePath(&__ImageBase, &module_path))
    LOG(ERROR) << "Module path: " << module_path.value();

  LOG(ERROR) << "RPC instance ID is \"" << id << "\".";

  base::Environment* env = base::Environment::Create();
  if (env) {
    std::string var;
    if (env->GetVar(::kSyzygyRpcInstanceIdEnvVar, &var)) {
      LOG(ERROR) << ::kSyzygyRpcInstanceIdEnvVar << " is \"" << var << "\".";
    } else {
      LOG(ERROR) << ::kSyzygyRpcInstanceIdEnvVar << " is not set.";
    }

    if (env->GetVar(::kSyzygyRpcSessionMandatoryEnvVar, &var)) {
      LOG(ERROR) << ::kSyzygyRpcSessionMandatoryEnvVar << " is \"" << var
                 << "\".";
    } else {
      LOG(ERROR) << ::kSyzygyRpcSessionMandatoryEnvVar << " is not set.";
    }
  }

  // Kill this process with prejudice. We need to be heavy handed here because
  // we are typically running under the loader lock, and most things won't
  // actually convince it to stop the entire process.
  ::TerminateProcess(::GetCurrentProcess(), 255);

  // We need this to avoid getting complaints about control paths missing a
  // return statement.
  return false;
}

}  // namespace client
}  // namespace trace

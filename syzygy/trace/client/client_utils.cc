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
#include "base/string_split.h"
#include "base/utf_string_conversions.h"
#include "base/win/pe_image.h"
#include "sawbuck/common/com_utils.h"
#include "syzygy/common/path_util.h"
#include "syzygy/core/file_util.h"

// http://blogs.msdn.com/oldnewthing/archive/2004/10/25/247180.aspx
extern "C" IMAGE_DOS_HEADER __ImageBase;

namespace trace {
namespace client {

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
  prefix->timestamp = ::GetTickCount();
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
    LOG(ERROR) << "VirtualQuery failed: " << com::LogWe(error) << ".";
    return false;
  }

  *module_base = mem_info.AllocationBase;

#ifndef NDEBUG
  base::win::PEImage image(*module_base);
  DCHECK(image.VerifyMagic());
#endif

  return true;
}

bool GetModulePath(void* module_base, FilePath* module_path) {
  DCHECK(module_base != NULL);
  DCHECK(module_path != NULL);

  HMODULE module = reinterpret_cast<HMODULE>(module_base);

  wchar_t buffer[1024];
  if (::GetMappedFileName(::GetCurrentProcess(), module_base, buffer,
                          arraysize(buffer)) == 0) {
    DWORD error = ::GetLastError();
    LOG(ERROR) << "GetMappedFileName failed: " << com::LogWe(error) << ".";
    return false;
  }

  FilePath device_path(buffer);
  if (!common::ConvertDevicePathToDrivePath(device_path, module_path))
    return false;

  return true;
}

std::string GetInstanceIdForModule(const FilePath& module_path) {
  size_t best_score = 0;
  std::string best_id;

  // Get the environment variable. If it's empty, we can return early.
  scoped_ptr<base::Environment> env(base::Environment::Create());
  std::string id_env_var;
  env->GetVar(::kSyzygyRpcInstanceIdEnvVar, &id_env_var);
  if (id_env_var.empty())
    return best_id;

  // Get the absolute path and the basename of the module. We will use these
  // for matching.
  FilePath abs_module_path(module_path);
  CHECK(file_util::AbsolutePath(&abs_module_path));
  FilePath base_module_path = module_path.BaseName();

  std::vector<std::string> ids;
  base::SplitString(id_env_var, ';', &ids);

  for (size_t i = 0; i < ids.size(); ++i) {
    if (ids[i].empty())
      continue;

    std::vector<std::string> split_id;
    base::SplitString(ids[i], ',', &split_id);

    size_t score = 0;

    if (split_id.size() == 1) {
      // This is a catch-all instance ID without a path.
      score = 1;
    } else if (split_id.size() == 2) {
      FilePath path(UTF8ToWide(split_id[0]));

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
      best_id = split_id.back();
    }
  }

  return best_id;
}

std::string GetInstanceIdForThisModule() {
  FilePath module_path;
  CHECK(GetModulePath(&__ImageBase, &module_path));

  std::string instance_id = GetInstanceIdForModule(module_path);

  return instance_id;
}

}  // namespace trace::client
}  // namespace trace

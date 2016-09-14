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
// This file defines the trace::agent_logger::Logger class which implements the
// Logger RPC interface.

#include "syzygy/trace/agent_logger/agent_logger.h"

#include <windows.h>  // NOLINT
#include <dbghelp.h>
#include <psapi.h>

#include "base/bind.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/win/scoped_handle.h"
#include "syzygy/common/com_utils.h"
#include "syzygy/common/dbghelp_util.h"
#include "syzygy/common/rpc/helpers.h"
#include "syzygy/kasko/minidump.h"
#include "syzygy/kasko/minidump_request.h"
#include "syzygy/kasko/api/client.h"
#include "syzygy/pe/find.h"

namespace trace {
namespace agent_logger {

namespace {

using ::common::rpc::GetInstanceString;

// A helper class to manage a SYMBOL_INFO structure.
template <size_t max_name_len>
class SymbolInfo {
 public:
  SymbolInfo() {
    static_assert(max_name_len > 0, "Maximum name length should be > 0.");
    static_assert(
        sizeof(buf_) - sizeof(info_) >= max_name_len * sizeof(wchar_t),
        "Not enough buffer space for max_name_len wchars");

    ::memset(buf_, 0, sizeof(buf_));
    info_.SizeOfStruct = sizeof(info_);
    info_.MaxNameLen = max_name_len;
  }

  PSYMBOL_INFO Get() { return &info_; }

  PSYMBOL_INFO operator->() { return &info_; }

 private:
  // SYMBOL_INFO is a variable length structure ending with a string (the
  // name of the symbol). The SYMBOL_INFO struct itself only declares the
  // first byte of the Name array, the rest we reserve by holding it in
  // union with a properly sized underlying buffer.
  union {
    SYMBOL_INFO info_;
    char buf_[sizeof(SYMBOL_INFO) + max_name_len * sizeof(wchar_t)];
  };
};

void GetSymbolInfo(HANDLE process,
                   uintptr_t frame_ptr,
                   std::string* name,
                   DWORD64* offset) {
  DCHECK(frame_ptr != NULL);
  DCHECK(name != NULL);
  DCHECK(offset != NULL);

  // Constants we'll need later.
  static const size_t kMaxNameLength = 256;
  SymbolInfo<kMaxNameLength> symbol;

  // Lookup the symbol by address.
  if (::SymFromAddr(process, frame_ptr, offset, symbol.Get())) {
    base::SStringPrintf(name, "%s+%ld", symbol->Name, *offset);
  } else {
    base::SStringPrintf(name, "(unknown)+%ld", *offset);
  }
}

void GetLineInfo(HANDLE process, DWORD_PTR frame, std::string* line_info) {
  DCHECK(frame != NULL);
  DCHECK(line_info != NULL);

  DWORD line_displacement = 0;
  IMAGEHLP_LINE64 line = {};
  line.SizeOfStruct = sizeof(IMAGEHLP_LINE64);
  if (::SymGetLineFromAddr64(process, frame, &line_displacement, &line)) {
    base::SStringPrintf(line_info, "%s:%d", line.FileName, line.LineNumber);
  } else {
    line_info->clear();
  }
}

// A callback function used with the StackWalk64 function. It is called when
// StackWalk64 needs to read memory from the address space of the process.
// http://msdn.microsoft.com/en-us/library/windows/desktop/ms680559.aspx
BOOL CALLBACK ReadProcessMemoryProc64(HANDLE process,
                                      DWORD64 base_address_64,
                                      PVOID buffer,
                                      DWORD size,
                                      LPDWORD bytes_read) {
  DCHECK(buffer != NULL);
  DCHECK(bytes_read != NULL);
  SIZE_T actual_bytes_read = 0;
  LPCVOID base_address = reinterpret_cast<LPCVOID>(base_address_64);
  if (::ReadProcessMemory(process, base_address, buffer, size,
                          &actual_bytes_read)) {
    *bytes_read = static_cast<DWORD>(actual_bytes_read);
    return TRUE;
  }

  // Maybe it was just a partial read, which isn't fatal.
  DWORD error = ::GetLastError();
  if (error == ERROR_PARTIAL_COPY) {
    *bytes_read = static_cast<DWORD>(actual_bytes_read);
    return TRUE;
  }

  // Nope, it was a real error.
  LOG(ERROR) << "Failed to read process memory: " << ::common::LogWe(error)
             << ".";
  return FALSE;
}

}  // namespace

AgentLogger::AgentLogger()
    : trace::common::Service(L"Logger"),
      destination_(NULL),
      symbolize_stack_traces_(true) {
}

AgentLogger::~AgentLogger() {
  if (state() != kStopped) {
    ignore_result(Stop());
    ignore_result(Join());
  }
}

bool AgentLogger::StartImpl() {
  LOG(INFO) << "Starting the logging service.";

  if (!InitRpc())
    return false;

  if (!StartRpc())
    return false;

  return true;
}

bool AgentLogger::StopImpl() {
  if (!StopRpc())
    return false;
  return true;
}

bool AgentLogger::JoinImpl() {
  // Finish processing all RPC events. If Stop() has previously been called
  // this will simply ensure that all outstanding requests are handled. If
  // Stop has not been called, this will continue (i.e., block) handling events
  // until someone else calls Stop() in another thread.
  if (!FinishRpc())
    return false;

  return true;
}

bool AgentLogger::AppendTrace(HANDLE process,
                              const uintptr_t* trace_data,
                              size_t trace_length,
                              std::string* message) {
  DCHECK(trace_data != NULL);
  DCHECK(message != NULL);

  // If we don't want to symbolize the stack traces then we just dump the
  // frame addresses.
  if (!symbolize_stack_traces_) {
    for (size_t i = 0; i < trace_length; ++i) {
      DWORD frame_ptr = trace_data[i];
      base::StringAppendF(message,
                          "    #%d 0x%012llx\n",
                          i,
                          frame_ptr);
    }
    return true;
  }

  // TODO(rogerm): Add an RPC session to the logger and its interface. This
  //     would serialize calls per process and provide a convenient mechanism
  //     for ensuring SymInitialize/Cleanup are called exactly once per client
  //     process.

  base::AutoLock auto_lock(symbol_lock_);

  // Make a unique "handle" for this use of the symbolizer.
  base::win::ScopedHandle unique_handle(
      ::OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE,
                    ::GetCurrentProcessId()));

  // Initializes the symbols for the process:
  //     - Defer symbol load until they're needed
  //     - Use undecorated names
  //     - Get line numbers
  ::SymSetOptions(SYMOPT_DEFERRED_LOADS | SYMOPT_UNDNAME | SYMOPT_LOAD_LINES);
  if (!::common::SymInitialize(unique_handle.Get(), NULL, true))
    return false;

  // Try to find the PDB of the running process, if it's found its path will be
  // appended to the current symbol search path. It is necessary because the
  // default search path doesn't include the directory of the caller by default.
  // TODO(sebmarchand): Also append the path of the PDBs of the modules loaded
  //     by the running process.
  WCHAR temp_path[MAX_PATH];
  if (::GetModuleFileNameEx(process, NULL, temp_path, MAX_PATH) != 0) {
    base::FilePath module_path(temp_path);
    base::FilePath temp_pdb_path;
    if (pe::FindPdbForModule(module_path, &temp_pdb_path)) {
      char current_search_path[1024];
      if (!::SymGetSearchPath(unique_handle.Get(), current_search_path,
                              arraysize(current_search_path))) {
        DWORD error = ::GetLastError();
        LOG(ERROR) << "Unable to get the current symbol search path: "
                   << ::common::LogWe(error);
        return false;
      }
      std::string new_pdb_search_path = std::string(current_search_path) + ";" +
                                        temp_pdb_path.DirName().AsUTF8Unsafe();
      if (!::SymSetSearchPath(unique_handle.Get(),
                              new_pdb_search_path.c_str())) {
        LOG(ERROR) << "Unable to set the symbol search path.";
        return false;
      }
    }
  }

  // Append each line of the trace to the message string.
  for (size_t i = 0; i < trace_length; ++i) {
    uintptr_t frame_ptr = trace_data[i];
    DWORD64 offset = 0;
    std::string symbol_name;
    std::string line_info;

    GetSymbolInfo(unique_handle.Get(), frame_ptr, &symbol_name, &offset);
    GetLineInfo(unique_handle.Get(), frame_ptr, &line_info);

    base::StringAppendF(message,
                        "    #%d 0x%012llx in %s%s%s\n",
                        i,
                        frame_ptr + offset,
                        symbol_name.c_str(),
                        line_info.empty() ? "" : " ",
                        line_info.c_str());
  }

  if (!::SymCleanup(unique_handle.Get())) {
    DWORD error = ::GetLastError();
    LOG(ERROR) << "SymCleanup failed: " << ::common::LogWe(error) << ".";
    return false;
  }

  return true;
}

bool AgentLogger::CaptureRemoteTrace(HANDLE process,
                                     CONTEXT* context,
                                     std::vector<uintptr_t>* trace_data) {
  DCHECK(context != NULL);
  DCHECK(trace_data != NULL);

  // TODO(rogerm): Add an RPC session to the logger and its interface. This
  //     would serialize calls per process and provide a convenient mechanism
  //     for ensuring SymInitialize/Cleanup are called exactly once per client
  //     process.

  trace_data->clear();
  trace_data->reserve(64);

  // If we don't want to symbolize the stack trace then there's no reason to
  // capture it.
  if (!symbolize_stack_traces_) {
    return true;
  }

  base::AutoLock auto_lock(symbol_lock_);

  // Make a unique "handle" for this use of the symbolizer.
  base::win::ScopedHandle unique_handle(
      ::OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE,
                    ::GetCurrentProcessId()));

  // Initializes the symbols for the process:
  //     - Defer symbol load until they're needed
  //     - Use undecorated names
  //     - Get line numbers
  ::SymSetOptions(SYMOPT_DEFERRED_LOADS | SYMOPT_UNDNAME | SYMOPT_LOAD_LINES);
  if (!::common::SymInitialize(unique_handle.Get(), NULL, true))
    return false;

  // Initialize a stack frame structure.
  STACKFRAME64 stack_frame;
  ::memset(&stack_frame, 0, sizeof(stack_frame));
#if defined(_WIN64)
  int machine_type = IMAGE_FILE_MACHINE_AMD64;
  stack_frame.AddrPC.Offset = context->Rip;
  stack_frame.AddrFrame.Offset = context->Rbp;
  stack_frame.AddrStack.Offset = context->Rsp;
#else
  int machine_type = IMAGE_FILE_MACHINE_I386;
  stack_frame.AddrPC.Offset = context->Eip;
  stack_frame.AddrFrame.Offset = context->Ebp;
  stack_frame.AddrStack.Offset = context->Esp;
#endif
  stack_frame.AddrPC.Mode = AddrModeFlat;
  stack_frame.AddrFrame.Mode = AddrModeFlat;
  stack_frame.AddrStack.Mode = AddrModeFlat;

  // Walk the stack.
  while (::StackWalk64(machine_type, unique_handle.Get(), NULL, &stack_frame,
                       context, &ReadProcessMemoryProc64,
                       &::SymFunctionTableAccess64, &::SymGetModuleBase64,
                       NULL)) {
    trace_data->push_back(stack_frame.AddrPC.Offset);
  }

  if (!::SymCleanup(unique_handle.Get())) {
    DWORD error = ::GetLastError();
    LOG(ERROR) << "SymCleanup failed: " << ::common::LogWe(error) << ".";
    return false;
  }

  // And we're done.
  return true;
}

bool AgentLogger::Write(const base::StringPiece& message) {
  DCHECK(destination_ != NULL);

  if (message.empty())
    return true;

  base::AutoLock auto_lock(write_lock_);

  size_t chars_written = ::fwrite(message.data(),
                                  sizeof(std::string::value_type),
                                  message.size(),
                                  destination_);

  if (chars_written != message.size()) {
    LOG(ERROR) << "Failed to write log message.";
    return false;
  }

  if (message[message.size() - 1] != '\n' &&
      ::fwrite("\n", 1, 1, destination_) != 1) {
    LOG(ERROR) << "Failed to append trailing newline.";
    return false;
  }

  ::fflush(destination_);

  return true;
}

bool AgentLogger::SaveMinidumpWithProtobufAndMemoryRanges(
    HANDLE process,
    base::ProcessId pid,
    DWORD tid,
    unsigned __int64 exc_ptr,
    const byte* protobuf,
    size_t protobuf_length,
    const void* const* memory_ranges_base_addresses,
    const size_t* memory_ranges_lengths,
    size_t memory_ranges_count) {
  DCHECK_NE(static_cast<const byte*>(nullptr), protobuf);
  DCHECK_NE(static_cast<const void* const*>(nullptr),
            memory_ranges_base_addresses);
  DCHECK_NE(static_cast<const size_t*>(nullptr), memory_ranges_lengths);

  // Copy the memory ranges into a vector.
  std::vector<kasko::api::MemoryRange> memory_ranges;
  for (size_t i = 0; i < memory_ranges_count; ++i) {
    kasko::api::MemoryRange memory_range = {memory_ranges_base_addresses[i],
                                            memory_ranges_lengths[i]};
    memory_ranges.push_back(memory_range);
  }

#ifndef _WIN64
  kasko::MinidumpRequest request;
  request.client_exception_pointers = true;
  request.exception_info_address = exc_ptr;
  if (protobuf_length) {
    kasko::MinidumpRequest::CustomStream custom_stream = {
        kasko::api::kProtobufStreamType, protobuf, protobuf_length};
    request.custom_streams.push_back(custom_stream);
  }

  request.type = kasko::MinidumpRequest::LARGER_DUMP_TYPE;

  DCHECK(!minidump_dir_.empty());
  // Create a temporary file to which to write the minidump. We'll rename it
  // to something recognizable when we're finished writing to it.
  base::FilePath temp_file_path;
  if (!base::CreateTemporaryFileInDir(minidump_dir_, &temp_file_path)) {
    LOG(ERROR) << "Could not create mini dump file in "
               << minidump_dir_.value();
    return false;
  }

  {
    base::AutoLock auto_lock(symbol_lock_);
    base::win::ScopedHandle target_process_handle(::OpenProcess(
        GetRequiredAccessForMinidumpType(request.type), FALSE, pid));
    if (!target_process_handle.IsValid()) {
      LOG(ERROR) << "Failed to open target process: " << ::common::LogWe()
                 << ".";
      return false;
    }
    CHECK(kasko::GenerateMinidump(temp_file_path, target_process_handle.Get(),
                                  tid, request));
  }

  // Rename the temporary file so that its recognizable as a dump.
  base::FilePath final_name(
      base::StringPrintf(L"minidump-%08u-%08u-%08u.dmp",
                         pid, tid, ::GetTickCount()));
  base::FilePath final_path = minidump_dir_.Append(final_name);
  if (base::Move(temp_file_path, final_path)) {
    std::string log_msg = base::StringPrintf(
        "A minidump has been written to %s.",
        final_path.AsUTF8Unsafe().c_str());
    Write(log_msg);
  } else {
    DWORD error = ::GetLastError();
    LOG(ERROR) << "Failed to move dump file to final location "
               << ::common::LogWe(error) << ".";
    return false;
  }
#endif

  return true;
}

bool AgentLogger::InitRpc() {
  RPC_STATUS status = RPC_S_OK;

  // Initialize the RPC protocol we want to use.
  std::wstring protocol(kLoggerRpcProtocol);
  std::wstring endpoint(
      GetInstanceString(kLoggerRpcEndpointRoot, instance_id()));

  VLOG(1) << "Initializing RPC endpoint '" << endpoint << "' "
          << "using the '" << protocol << "' protocol.";
  status = ::RpcServerUseProtseqEp(
      ::common::rpc::AsRpcWstr(&protocol[0]), RPC_C_LISTEN_MAX_CALLS_DEFAULT,
      ::common::rpc::AsRpcWstr(&endpoint[0]), NULL /* Security descriptor. */);
  if (status != RPC_S_OK && status != RPC_S_DUPLICATE_ENDPOINT) {
    LOG(ERROR) << "Failed to init RPC protocol: " << ::common::LogWe(status)
               << ".";
    return false;
  }

  // Register the logger interface.
  VLOG(1) << "Registering the Logger interface.";
  status = ::RpcServerRegisterIf(
      LoggerService_Logger_v1_0_s_ifspec, NULL, NULL);
  if (status != RPC_S_OK) {
    LOG(ERROR) << "Failed to register RPC interface: "
               << ::common::LogWe(status) << ".";
    return false;
  }

  // Register the logger control interface.
  VLOG(1) << "Registering the Logger Control interface.";
  status = ::RpcServerRegisterIf(
      LoggerService_LoggerControl_v1_0_s_ifspec, NULL, NULL);
  if (status != RPC_S_OK) {
    LOG(ERROR) << "Failed to register RPC interface: "
               << ::common::LogWe(status) << ".";
    return false;
  }

  OnInitialized();

  return true;
}

bool AgentLogger::StartRpc() {
  // This method must be called by the owning thread, so no need to otherwise
  // synchronize the method invocation.
  VLOG(1) << "Starting the RPC server.";

  RPC_STATUS status = ::RpcServerListen(
      1,  // Minimum number of handler threads.
      RPC_C_LISTEN_MAX_CALLS_DEFAULT,
      TRUE);

  if (status != RPC_S_OK) {
    LOG(ERROR) << "Failed to run RPC server: " << ::common::LogWe(status)
               << ".";
    ignore_result(FinishRpc());
    return false;
  }

  // Signal that the RPC is up and running.
  DCHECK(!started_event_.IsValid());
  std::wstring event_name;
  GetSyzygyAgentLoggerEventName(instance_id(), &event_name);
  started_event_.Set(::CreateEvent(NULL, TRUE, FALSE, event_name.c_str()));
  if (!started_event_.IsValid()) {
    DWORD error = ::GetLastError();
    LOG(ERROR) << "Failed to create event: " << ::common::LogWe(error) << ".";
    return false;
  }
  BOOL success = ::SetEvent(started_event_.Get());
  DCHECK(success);

  // Invoke the callback for the logger started event, giving it a chance to
  // abort the startup.
  if (!OnStarted()) {
    ignore_result(StopRpc());
    ignore_result(FinishRpc());
    return false;
  }

  return true;
}

bool AgentLogger::StopRpc() {
  // This method may be called by any thread, but it does not inspect or modify
  // the internal state of the Logger; so, no synchronization is required.
  VLOG(1) << "Requesting an asynchronous shutdown of the logging service.";

  BOOL success = ::ResetEvent(started_event_.Get());
  DCHECK(success);

  RPC_STATUS status = ::RpcMgmtStopServerListening(NULL);
  if (status != RPC_S_OK) {
    LOG(ERROR) << "Failed to stop the RPC server: "
                << ::common::LogWe(status) << ".";
    return false;
  }

  if (!OnInterrupted())
    return false;

  return true;
}

bool AgentLogger::FinishRpc() {
  bool error = false;
  RPC_STATUS status = RPC_S_OK;

  // Run the RPC server to completion. This is a blocking call which will only
  // terminate after someone calls StopRpc() on another thread.
  status = RpcMgmtWaitServerListen();
  if (status != RPC_S_OK) {
    LOG(ERROR) << "Failed to wait for RPC server shutdown: "
                << ::common::LogWe(status) << ".";
    error = true;
  }

  status = ::RpcServerUnregisterIf(
      LoggerService_Logger_v1_0_s_ifspec, NULL, FALSE);
  if (status != RPC_S_OK) {
    LOG(ERROR) << "Failed to unregister the AgentLogger RPC interface: "
                << ::common::LogWe(status) << ".";
    error = true;
  }

  status = ::RpcServerUnregisterIf(
      LoggerService_LoggerControl_v1_0_s_ifspec, NULL, FALSE);
  if (status != RPC_S_OK) {
    LOG(ERROR) << "Failed to unregister AgentLogger Control RPC interface: "
                << ::common::LogWe(status) << ".";
    error = true;
  }

  LOG(INFO) << "The logging service has stopped.";
  if (!OnStopped())
    error = true;

  return !error;
}

void AgentLogger::GetSyzygyAgentLoggerEventName(const base::StringPiece16& id,
                                                std::wstring* output) {
  DCHECK(output != NULL);
  const wchar_t* const kAgentLoggerSvcEvent = L"syzygy-agent-logger-svc-event";

  output->assign(kAgentLoggerSvcEvent);
  if (!id.empty()) {
    output->append(1, '-');
    output->append(id.begin(), id.end());
  }
}

}  // namespace agent_logger
}  // namespace trace

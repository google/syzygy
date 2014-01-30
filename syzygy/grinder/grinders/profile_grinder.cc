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

#include "syzygy/grinder/grinders/profile_grinder.h"

#include "base/at_exit.h"
#include "base/command_line.h"
#include "base/string_util.h"
#include "base/stringprintf.h"
#include "base/strings/utf_string_conversions.h"
#include "base/win/scoped_bstr.h"
#include "syzygy/common/com_utils.h"
#include "syzygy/pe/find.h"

namespace grinder {
namespace grinders {

using base::win::ScopedBstr;
using base::win::ScopedComPtr;
using trace::parser::AbsoluteAddress64;
using trace::parser::ParseEventHandler;
using pe::ModuleInformation;

namespace {

// Compares module information without regard to base address.
// Used to canonicalize module information, even across processes, or multiple
// loads for the same module at different addresses in the same process.
bool ModuleInformationKeyLess(const ModuleInformation& a,
                              const ModuleInformation& b) {
  if (a.module_size > b.module_size)
    return false;
  if (a.module_size < b.module_size)
    return true;

  if (a.module_checksum > b.module_checksum)
    return false;
  if (a.module_checksum < b.module_checksum)
    return true;

  if (a.module_time_date_stamp > b.module_time_date_stamp)
    return false;
  if (a.module_time_date_stamp < b.module_time_date_stamp)
    return true;

  return a.path < b.path;
}

}  // namespace

ProfileGrinder::CodeLocation::CodeLocation()
    : process_id_(0), symbol_id_(0), symbol_offset_(0), is_symbol_(false) {
}

void ProfileGrinder::CodeLocation::Set(
    uint32 process_id, uint32 symbol_id, size_t symbol_offset) {
  is_symbol_ = true;
  process_id_ = process_id;
  symbol_id_ = symbol_id;
  symbol_offset_ = symbol_offset;
}

void ProfileGrinder::CodeLocation::Set(
    const pe::ModuleInformation* module, RVA rva) {
  is_symbol_ = false;
  module_ = module;
  rva_ = rva;
  symbol_offset_ = 0;
}

std::string ProfileGrinder::CodeLocation::ToString() const {
  if (is_symbol()) {
    return base::StringPrintf("Symbol: %d, %d", process_id(), symbol_id());
  } else {
    return base::StringPrintf("Module/RVA: 0x%08X, 0x%08X", module(), rva());
  }
}

bool ProfileGrinder::CodeLocation::operator<(const CodeLocation& o) const {
  if (is_symbol_ < o.is_symbol_)
    return true;
  else if (is_symbol_ > o.is_symbol_)
    return false;

  DCHECK_EQ(o.is_symbol_, is_symbol_);
  if (is_symbol_) {
    if (process_id_ > o.process_id_)
      return false;
    if (process_id_ < o.process_id_)
      return true;

    if (symbol_id_ > o.symbol_id_)
      return false;
    if (symbol_id_ < o.symbol_id_)
      return true;

    return symbol_offset_ < o.symbol_offset_;
  } else {
    if (module_ > o.module_)
      return false;
    if (module_ < o.module_)
      return true;
    return rva_ < o.rva_;
  }
}

void ProfileGrinder::CodeLocation::operator=(const CodeLocation& o) {
  is_symbol_ = o.is_symbol_;
  symbol_offset_ = o.symbol_offset_;
  if (is_symbol_) {
    process_id_ = o.process_id_;
    symbol_id_ = o.symbol_id_;
  } else {
    rva_ = o.rva_;
    module_ = o.module_;
  }
}

ProfileGrinder::PartData::PartData()
    : process_id_(0), thread_id_(0) {
}

ProfileGrinder::ProfileGrinder()
    : parser_(NULL),
      modules_(ModuleInformationKeyLess),
      thread_parts_(true) {
}

ProfileGrinder::~ProfileGrinder() {
}

bool ProfileGrinder::ParseCommandLine(const CommandLine* command_line) {
  thread_parts_ = command_line->HasSwitch("thread-parts");
  return true;
}

void ProfileGrinder::SetParser(Parser* parser) {
  DCHECK(parser != NULL);
  parser_ = parser;
}

bool ProfileGrinder::Grind() {
  if (!ResolveCallers()) {
    LOG(ERROR) << "Error resolving callers.";
    return false;
  }
  return true;
}

bool ProfileGrinder::GetSessionForModule(const ModuleInformation* module,
                                         IDiaSession** session_out) {
  DCHECK(module != NULL);
  DCHECK(session_out != NULL);
  DCHECK(*session_out == NULL);

  ModuleSessionMap::const_iterator it(
      module_sessions_.find(module));

  if (it == module_sessions_.end()) {
    ScopedComPtr<IDiaDataSource> source;
    HRESULT hr = source.CreateInstance(CLSID_DiaSource);
    if (FAILED(hr)) {
      LOG(ERROR) << "Failed to create DiaSource: "
                 << common::LogHr(hr) << ".";
      return false;
    }

    base::FilePath module_path;
    if (!pe::FindModuleBySignature(*module, &module_path) ||
        module_path.empty()) {
      LOG(ERROR) << "Unable to find module matching signature.";
      return false;
    }

    ScopedComPtr<IDiaSession> new_session;
    // We first try loading straight-up for the module. If the module is at
    // this path and the symsrv machinery is available, this will bring that
    // machinery to bear.
    // The downside is that if the module at this path does not match the
    // original module, we may load the wrong symbol information for the
    // module.
    hr = source->loadDataForExe(module_path.value().c_str(), NULL, NULL);
    if (SUCCEEDED(hr)) {
        hr = source->openSession(new_session.Receive());
        if (FAILED(hr))
          LOG(ERROR) << "Failure in openSession: " << common::LogHr(hr) << ".";
    } else {
      DCHECK(FAILED(hr));

      base::FilePath pdb_path;
      if (!pe::FindPdbForModule(module_path, &pdb_path) ||
          pdb_path.empty()) {
        LOG(ERROR) << "Unable to find PDB for module \""
                   << module_path.value() << "\".";
      }

      hr = source->loadDataFromPdb(pdb_path.value().c_str());
      if (SUCCEEDED(hr)) {
        hr = source->openSession(new_session.Receive());
        if (FAILED(hr))
          LOG(ERROR) << "Failure in openSession: " << common::LogHr(hr) << ".";
      } else {
        LOG(WARNING) << "Failure in loadDataFromPdb('"
                     << module_path.value().c_str() << "'): "
                     << common::LogHr(hr) << ".";
      }
    }

    DCHECK((SUCCEEDED(hr) && new_session.get() != NULL) ||
           (FAILED(hr) && new_session.get() == NULL));

    // We store an entry to the cache irrespective of whether we succeeded
    // in opening a session above. This allows us to cache the failures, which
    // means we attempt to load each module only once, and consequently log
    // each failing module only once.
    it = module_sessions_.insert(
        std::make_pair(module, new_session)).first;
  }
  DCHECK(it != module_sessions_.end());

  if (it->second.get() == NULL) {
    // A negative session cache entry - we were previously unable to
    // load this module.
    return false;
  }

  *session_out = it->second;
  (*session_out)->AddRef();

  return true;
}

ProfileGrinder::PartData* ProfileGrinder::FindOrCreatePart(DWORD process_id,
                                                           DWORD thread_id) {
  if (!thread_parts_) {
    process_id = 0;
    thread_id = 0;
  }

  // Lookup the part to aggregate to.
  PartKey key(process_id, thread_id);
  PartDataMap::iterator it = parts_.find(key);
  if (it == parts_.end()) {
    PartData part;
    part.process_id_ = process_id;
    part.thread_id_ = thread_id;

    it = parts_.insert(std::make_pair(key, part)).first;
  }

  return &it->second;
}

bool ProfileGrinder::GetFunctionSymbolByRVA(IDiaSession* session,
                                            RVA address,
                                            IDiaSymbol** symbol) {
  DCHECK(session != NULL);
  DCHECK(symbol != NULL && *symbol == NULL);

  ScopedComPtr<IDiaSymbol> function;
  HRESULT hr = session->findSymbolByRVA(address,
                                        SymTagFunction,
                                        function.Receive());
  if (FAILED(hr) || function.get() == NULL) {
    // No private function, let's try for a public symbol.
    hr = session->findSymbolByRVA(address,
                                  SymTagPublicSymbol,
                                  function.Receive());
    if (FAILED(hr))
      return false;
  }
  if (function.get() == NULL) {
    LOG(ERROR) << "NULL function returned from findSymbolByRVA.";
    return false;
  }

  *symbol = function.Detach();

  return true;
}

bool ProfileGrinder::GetFunctionForCaller(const CallerLocation& caller,
                                          FunctionLocation* function,
                                          size_t* line) {
  DCHECK(function != NULL);
  DCHECK(line != NULL);

  if (caller.is_symbol()) {
    // The function symbol for a caller is simply the same symbol with a
    // zero offset.
    function->Set(caller.process_id(), caller.symbol_id(), 0);
    return true;
  }

  DCHECK(!caller.is_symbol());

  if (caller.module() == NULL) {
    // If the module is unknown, we fake a function per every K of memory.
    // Turns out that V8 generates some code outside the JS heap, and as of
    // June 2013, does not push symbols for the code.
    function->Set(NULL, caller.rva() & ~1023);
    *line = 0;
    return true;
  }

  ScopedComPtr<IDiaSession> session;
  if (!GetSessionForModule(caller.module(), session.Receive()))
    return false;

  ScopedComPtr<IDiaSymbol> function_sym;
  if (!GetFunctionSymbolByRVA(session.get(),
                              caller.rva(),
                              function_sym.Receive())) {
    LOG(ERROR) << "No symbol info available for function in module '"
               << caller.module()->path << "'";
  }

  // Get the RVA of the function.
  DWORD rva = 0;
  HRESULT hr = function_sym->get_relativeVirtualAddress(&rva);
  if (FAILED(hr)) {
    LOG(ERROR) << "Failure in get_relativeVirtualAddress: "
               << common::LogHr(hr) << ".";
    return false;
  }

  // Return the module/rva we found.
  function->Set(caller.module(), rva);

  ULONGLONG length = 0;
  hr = function_sym->get_length(&length);
  if (FAILED(hr)) {
    LOG(ERROR) << "Failure in get_length: " << common::LogHr(hr) << ".";
    return false;
  }

  DWORD line_number = 0;
  if (length != 0) {
    ScopedComPtr<IDiaEnumLineNumbers> enum_lines;

    hr = session->findLinesByRVA(caller.rva(), length, enum_lines.Receive());
    if (FAILED(hr)) {
      LOG(ERROR) << "Failure in findLinesByRVA: " << common::LogHr(hr) << ".";
      return false;
    }

    ScopedComPtr<IDiaLineNumber> line;
    ULONG fetched = 0;
    hr = enum_lines->Next(1, line.Receive(), &fetched);
    if (FAILED(hr)) {
      LOG(ERROR) << "Failure in IDiaLineNumber::Next: "
                 << common::LogHr(hr) << ".";
      return false;
    }

    if (fetched == 1) {
      hr = line->get_lineNumber(&line_number);
      if (FAILED(hr)) {
        LOG(ERROR) << "Failure in get_lineNumber: " << common::LogHr(hr) << ".";
        return false;
      }
    } else if (fetched != 0) {
      NOTREACHED() << "IDiaLineNumber::Next unexpectedly returned "
                   << fetched << " elements.";
    }
  }

  *line = line_number;
  return true;
}

bool ProfileGrinder::GetInfoForFunction(const FunctionLocation& function,
                                        std::wstring* function_name,
                                        std::wstring* file_name,
                                        size_t* line) {
  DCHECK(function_name != NULL);
  DCHECK(file_name != NULL);
  DCHECK(line != NULL);

  if (function.is_symbol()) {
    DCHECK_EQ(0U, function.symbol_offset());

    DynamicSymbolKey key(function.process_id(), function.symbol_id());
    DynamicSymbolMap::iterator it(dynamic_symbols_.find(key));

    if (it != dynamic_symbols_.end()) {
      // Get the function name.
      *function_name = base::UTF8ToWide(it->second);
      *file_name = L"*JAVASCRIPT*";
      *line = 0;
    } else {
      LOG(ERROR) << "No symbol info available for symbol "
                 << function.symbol_id() << " in process "
                 << function.process_id();
      return false;
    }

    return true;
  }

  DCHECK(!function.is_symbol());

  if (function.module() == NULL) {
    *function_name = base::StringPrintf(L"FakeFunction_0x%08X", function.rva());
    *file_name = L"*UNKNOWN*";
    return true;
  }

  ScopedComPtr<IDiaSession> session;
  if (!GetSessionForModule(function.module(), session.Receive()))
    return false;

  ScopedComPtr<IDiaSymbol> function_sym;
  if (!GetFunctionSymbolByRVA(session.get(),
                              function.rva(),
                              function_sym.Receive())) {
    LOG(ERROR) << "No symbol info available for function in module '"
               << function.module()->path << "'";
    return false;
  }

  ScopedBstr function_name_bstr;
  HRESULT hr = function_sym->get_name(function_name_bstr.Receive());
  if (FAILED(hr)) {
    LOG(ERROR) << "Failure in get_name: " << common::LogHr(hr) << ".";
    return false;
  }

  *function_name = common::ToString(function_name_bstr);

  ULONGLONG length = 0;
  hr = function_sym->get_length(&length);
  if (FAILED(hr)) {
    LOG(ERROR) << "Failure in get_length: " << common::LogHr(hr) << ".";
    return false;
  }

  ScopedBstr file_name_bstr;
  DWORD line_number = 0;
  if (length != 0) {
    ScopedComPtr<IDiaEnumLineNumbers> enum_lines;

    hr = session->findLinesByRVA(function.rva(),
                                 length,
                                 enum_lines.Receive());
    if (FAILED(hr)) {
      LOG(ERROR) << "Failure in findLinesByRVA: " << common::LogHr(hr) << ".";
      return false;
    }

    ScopedComPtr<IDiaLineNumber> line;
    ULONG fetched = 0;
    hr = enum_lines->Next(1, line.Receive(), &fetched);
    if (FAILED(hr)) {
      LOG(ERROR) << "Failure in IDialineNumber::Next: "
                 << common::LogHr(hr) << ".";
      return false;
    }
    if (fetched == 1) {
      hr = line->get_lineNumber(&line_number);
      if (FAILED(hr)) {
        LOG(ERROR) << "Failure in get_lineNumber: " << common::LogHr(hr) << ".";
        return false;
      }
      ScopedComPtr<IDiaSourceFile> source_file;
      hr = line->get_sourceFile(source_file.Receive());
      if (FAILED(hr)) {
        LOG(ERROR) << "Failure in get_sourceFile: " << common::LogHr(hr) << ".";
        return false;
      }
      hr = source_file->get_fileName(file_name_bstr.Receive());
      if (FAILED(hr)) {
        LOG(ERROR) << "Failure in get_fileName: " << common::LogHr(hr) << ".";
        return false;
      }
    }
  }

  *file_name = common::ToString(file_name_bstr);
  *line = line_number;
  return true;
}

bool ProfileGrinder::ResolveCallers() {
  PartDataMap::iterator it = parts_.begin();
  for (; it != parts_.end(); ++it) {
    if (!ResolveCallersForPart(&it->second))
      return false;
  }

  return true;
}

bool ProfileGrinder::ResolveCallersForPart(PartData* part) {
  // We start by iterating all the edges, connecting them up to their caller,
  // and subtracting the edge metric(s) to compute the inclusive metrics for
  // each function.
  InvocationEdgeMap::iterator edge_it(part->edges_.begin());
  for (; edge_it != part->edges_.end(); ++edge_it) {
    InvocationEdge& edge = edge_it->second;
    FunctionLocation function;
    if (GetFunctionForCaller(edge.caller, &function, &edge.line)) {
      InvocationNodeMap::iterator node_it(part->nodes_.find(function));
      if (node_it == part->nodes_.end()) {
        // This is a fringe node - e.g. this is a non-instrumented caller
        // calling into an instrumented function. Create the node now,
        // but note that we won't have any metrics recorded for the function
        // and must be careful not to try and tally exclusive stats for it.
        node_it = part->nodes_.insert(
            std::make_pair(function, InvocationNode())).first;

        node_it->second.function = function;
        DCHECK_EQ(0, node_it->second.metrics.num_calls);
        DCHECK_EQ(0, node_it->second.metrics.cycles_sum);
      }

      InvocationNode& node = node_it->second;

      // Hook the edge up to the node's list of outgoing edges.
      edge.next_call = node.first_call;
      node.first_call = &edge;

      // Make the function's cycle count exclusive, by subtracting all
      // the outbound (inclusive) cycle counts from the total. We make
      // special allowance for the "fringe" nodes mentioned above, by
      // noting they have no recorded calls.
      if (node.metrics.num_calls != 0) {
        node.metrics.cycles_sum -= edge.metrics.cycles_sum;
      }
    } else {
      // TODO(siggi): The profile instrumentation currently doesn't record
      //     sufficient module information that we can resolve calls from
      //     system and dependent modules.
      LOG(WARNING) << "Found no info for module: '"
                   << edge.caller.module()->path << "'.";
    }
  }

  return true;
}

bool ProfileGrinder::OutputData(FILE* file) {
  // Output the file header.

  bool succeeded = true;
  PartDataMap::iterator it = parts_.begin();
  for (; it != parts_.end(); ++it) {
    if (!OutputDataForPart(it->second, file)) {
      // Keep going despite problems in output
      succeeded = false;
    }
  }

  return succeeded;
}

bool ProfileGrinder::OutputDataForPart(const PartData& part, FILE* file) {
  // TODO(siggi): Output command line here.
  ::fprintf(file, "pid: %d\n", part.process_id_);
  if (part.thread_id_ != 0)
    ::fprintf(file, "thread: %d\n", part.thread_id_);
  ::fprintf(file, "events: Calls Cycles Cycles-Min Cycles-Max\n");

  if (!part.thread_name_.empty())
    ::fprintf(file, "desc: Trigger: %s\n", part.thread_name_.c_str());

  // Walk the nodes and output the data.
  InvocationNodeMap::const_iterator node_it(part.nodes_.begin());
  for (; node_it != part.nodes_.end(); ++node_it) {
    const InvocationNode& node = node_it->second;
    std::wstring function_name;
    std::wstring file_name;
    size_t line = 0;
    if (GetInfoForFunction(node.function, &function_name, &file_name, &line)) {
      // Rewrite file path to use forward slashes instead of back slashes.
      ::ReplaceChars(file_name, L"\\", L"/", &file_name);

      // Output the function information.
      ::fprintf(file, "fl=%ws\n", file_name.c_str());
      ::fprintf(file, "fn=%ws\n", function_name.c_str());
      ::fprintf(file, "%d %I64d %I64d %I64d %I64d\n", line,
                node.metrics.num_calls, node.metrics.cycles_sum,
                node.metrics.cycles_min, node.metrics.cycles_max);

      // Output the call information from this function.
      const InvocationEdge* call = node.first_call;
      for (; call != NULL; call = call->next_call) {
        if (GetInfoForFunction(call->function,
                               &function_name,
                               &file_name,
                               &line)) {

          // Rewrite file path to use forward slashes instead of back slashes.
          ::ReplaceChars(file_name, L"\\", L"/", &file_name);

          ::fprintf(file, "cfl=%ws\n", file_name.c_str());
          ::fprintf(file, "cfn=%ws\n", function_name.c_str());
          ::fprintf(file, "calls=%d %d\n", call->metrics.num_calls, line);
          ::fprintf(file, "%d %I64d %I64d %I64d %I64d\n", call->line,
                    call->metrics.num_calls, call->metrics.cycles_sum,
                    call->metrics.cycles_min, call->metrics.cycles_max);
        }
      }
    } else {
      LOG(ERROR) << "Unable to resolve function.";
      return false;
    }
  }

  return true;
}

void ProfileGrinder::OnInvocationBatch(base::Time time,
                                       DWORD process_id,
                                       DWORD thread_id,
                                       size_t num_invocations,
                                       const TraceBatchInvocationInfo* data) {
  PartData* part = FindOrCreatePart(process_id, thread_id);
  DCHECK(data != NULL);

  // Process and aggregate the individual invocation entries.
  for (size_t i = 0; i < num_invocations; ++i) {
    const InvocationInfo& info = data->invocations[i];
    if (info.caller == NULL || info.function == NULL) {
      // This may happen due to a termination race when the traces are captured.
      LOG(WARNING) << "Empty invocation record. Record " << i << " of " <<
          num_invocations << ".";
      break;
    }

    FunctionLocation function;
    if ((info.flags & kFunctionIsSymbol) != 0) {
      // The function is a dynamic symbol
      function.Set(process_id, info.function_symbol_id, 0);
    } else {
      // The function is native.
      AbsoluteAddress64 function_addr =
          reinterpret_cast<AbsoluteAddress64>(info.function);

      ConvertToModuleRVA(process_id, function_addr, &function);
    }

    CallerLocation caller;
    if ((info.flags & kCallerIsSymbol) != 0) {
      // The caller is a dynamic symbol.
      caller.Set(process_id, info.caller_symbol_id, info.caller_offset);
    } else {
      // The caller is a native function.
      AbsoluteAddress64 caller_addr =
          reinterpret_cast<AbsoluteAddress64>(info.caller);
      ConvertToModuleRVA(process_id, caller_addr, &caller);
    }

    AggregateEntryToPart(function, caller, info, part);
  }
}

void ProfileGrinder::OnThreadName(base::Time time,
                                  DWORD process_id,
                                  DWORD thread_id,
                                  const base::StringPiece& thread_name) {
  if (!thread_parts_)
    return;

  PartData* part = FindOrCreatePart(process_id, thread_id);
  part->thread_name_ = thread_name.as_string();
}

void ProfileGrinder::OnDynamicSymbol(DWORD process_id,
                                     uint32 symbol_id,
                                     const base::StringPiece& symbol_name) {
  DynamicSymbolKey key(process_id, symbol_id);

  dynamic_symbols_[key].assign(symbol_name.begin(), symbol_name.end());
}

void ProfileGrinder::AggregateEntryToPart(const FunctionLocation& function,
                                          const CallerLocation& caller,
                                          const InvocationInfo& info,
                                          PartData* part) {
  // Have we recorded this node before?
  InvocationNodeMap::iterator node_it(part->nodes_.find(function));
  if (node_it != part->nodes_.end()) {
    // Yups, we've seen this edge before.
    // Aggregate the new data with the old.
    InvocationNode& found = node_it->second;
    found.metrics.num_calls += info.num_calls;
    found.metrics.cycles_min = std::min(found.metrics.cycles_min,
                                        info.cycles_min);
    found.metrics.cycles_max = std::max(found.metrics.cycles_max,
                                        info.cycles_max);
    found.metrics.cycles_sum += info.cycles_sum;
  } else {
    // Nopes, we haven't seen this pair before, insert it.
    InvocationNode& node = part->nodes_[function];
    node.function = function;
    node.metrics.num_calls = info.num_calls;
    node.metrics.cycles_min = info.cycles_min;
    node.metrics.cycles_max = info.cycles_max;
    node.metrics.cycles_sum = info.cycles_sum;
  }

  InvocationEdgeKey key(function, caller);

  // Have we recorded this edge before?
  InvocationEdgeMap::iterator edge_it(part->edges_.find(key));
  if (edge_it != part->edges_.end()) {
    // Yups, we've seen this edge before.
    // Aggregate the new data with the old.
    InvocationEdge& found = edge_it->second;
    found.metrics.num_calls += info.num_calls;
    found.metrics.cycles_min = std::min(found.metrics.cycles_min,
                                        info.cycles_min);
    found.metrics.cycles_max = std::max(found.metrics.cycles_max,
                                        info.cycles_max);
    found.metrics.cycles_sum += info.cycles_sum;
  } else {
    // Nopes, we haven't seen this edge before, insert it.
    InvocationEdge& edge = part->edges_[key];
    edge.function = function;
    edge.caller = caller;
    edge.metrics.num_calls = info.num_calls;
    edge.metrics.cycles_min = info.cycles_min;
    edge.metrics.cycles_max = info.cycles_max;
    edge.metrics.cycles_sum = info.cycles_sum;
  }
}

void ProfileGrinder::ConvertToModuleRVA(uint32 process_id,
                                        AbsoluteAddress64 addr,
                                        CodeLocation* rva) {
  DCHECK(rva != NULL);

  const ModuleInformation* module =
      parser_->GetModuleInformation(process_id, addr);

  if (module == NULL) {
    // We have no module information for this address.
    rva->Set(NULL, addr);
    return;
  }

  // And find or record the canonical module information
  // for this module.
  ModuleInformationSet::iterator it(modules_.find(*module));
  if (it == modules_.end()) {
    it = modules_.insert(*module).first;
  }
  DCHECK(it != modules_.end());

  rva->Set(&(*it), static_cast<RVA>(addr - module->base_address.value()));
}

}  // namespace grinders
}  // namespace grinder

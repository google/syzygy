// Copyright 2014 Google Inc. All Rights Reserved.
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

#include "syzygy/refinery/unittest_util.h"

#include <windows.h>  // NOLINT
#include <dbghelp.h>

#include <cstring>
#include <vector>

#include "base/base_switches.h"
#include "base/command_line.h"
#include "base/logging.h"
#include "base/files/file_util.h"
#include "base/files/scoped_temp_dir.h"
#include "base/numerics/safe_math.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/utf_string_conversions.h"
#include "base/test/multiprocess_test.h"
#include "base/test/test_timeouts.h"
#include "gtest/gtest.h"
#include "syzygy/common/com_utils.h"
#include "testing/multiprocess_func_list.h"

namespace testing {

namespace {

void PopulateContext(std::string* context_bytes, int base_offset) {
  DCHECK(context_bytes != nullptr);

  context_bytes->resize(sizeof(CONTEXT));
  CONTEXT* ctx = reinterpret_cast<CONTEXT*>(&context_bytes->at(0));
  ctx->ContextFlags = CONTEXT_SEGMENTS | CONTEXT_INTEGER | CONTEXT_CONTROL;
  ctx->SegGs = base_offset + 1;
  ctx->SegFs = base_offset + 2;
  ctx->SegEs = base_offset + 3;
  ctx->SegDs = base_offset + 4;
  ctx->Edi = base_offset + 11;
  ctx->Esi = base_offset + 12;
  ctx->Ebx = base_offset + 13;
  ctx->Edx = base_offset + 14;
  ctx->Ecx = base_offset + 15;
  ctx->Eax = base_offset + 16;
  ctx->Ebp = base_offset + 21;
  ctx->Eip = base_offset + 22;
  ctx->SegCs = base_offset + 23;
  ctx->EFlags = base_offset + 24;
  ctx->Esp = base_offset + 25;
  ctx->SegSs = base_offset + 26;
}

using MemorySpecification = MinidumpSpecification::MemorySpecification;
using ThreadSpecification = MinidumpSpecification::ThreadSpecification;
using ExceptionSpecification = MinidumpSpecification::ExceptionSpecification;
using ModuleSpecification = MinidumpSpecification::ModuleSpecification;

// TODO(manzagop): ensure on destruction or finalizing that the allocations are
// actually reflected in the file. At this point, allocating without writing
// would leave the file short.
class MinidumpSerializer {
 public:
  typedef RVA Position;

  MinidumpSerializer();

  // @pre @p dir must be a valid directory.
  bool Initialize(const base::ScopedTempDir& dir);
  bool SerializeThreads(const std::vector<ThreadSpecification>& threads);
  bool SerializeMemory(const std::vector<MemorySpecification>& regions);
  bool SerializeModules(const std::vector<ModuleSpecification>& modules);
  bool SerializeExceptions(
      const std::vector<ExceptionSpecification>& exceptions);
  bool Finalize();

  const base::FilePath& path() const { return path_; }

 private:
  static const Position kHeaderPos = 0U;

  void SerializeDirectory();
  void SerializeHeader();

  Position Allocate(size_t size_bytes);

  // Allocate new space and write to it.
  template <class DataType>
  Position Append(const DataType& data);
  // @pre @p data must not be empty.
  template <class DataType>
  Position AppendVec(const std::vector<DataType>& data);
  // @pre @p elements must not be empty.
  template <class DataType>
  Position AppendListStream(MINIDUMP_STREAM_TYPE type,
                            const std::vector<DataType>& elements);
  Position AppendBytes(base::StringPiece data);
  Position AppendMinidumpString(base::StringPiece utf8);

  // Write to already allocated space.
  template <class DataType>
  void Write(Position pos, const DataType& data);
  void WriteBytes(Position pos, size_t size_bytes, const void* data);

  bool IncrementCursor(size_t size_bytes);

  // Gets the position of an address range which is fully contained in a
  // serialized range.
  // @pre is_serialize_memory_invoked_ must be true.
  // @param range the range for which to get the rva.
  // @param pos the returned position.
  // returns true on success, false otherwise.
  bool GetPos(const refinery::AddressRange& range, Position* pos) const;

  void AddDirectoryEntry(MINIDUMP_STREAM_TYPE type, Position pos, size_t size);

  bool succeeded() const { return !failed_; }

  bool failed_;
  bool is_serialize_memory_invoked_;

  std::vector<MINIDUMP_DIRECTORY> directory_;

  Position cursor_;  // The next allocatable position.
  base::FilePath path_;
  base::ScopedFILE file_;

  std::map<refinery::AddressRange, Position> memory_positions_;
};

MinidumpSerializer::MinidumpSerializer()
    : failed_(true), is_serialize_memory_invoked_(false), cursor_(0U) {
}

bool MinidumpSerializer::Initialize(const base::ScopedTempDir& dir) {
  DCHECK(dir.IsValid());

  failed_ = false;
  is_serialize_memory_invoked_ = false;
  directory_.clear();

  // Create the backing file.
  cursor_ = 0U;
  if (!CreateTemporaryFileInDir(dir.path(), &path_)) {
    failed_ = true;
    return false;
  }

  file_.reset(base::OpenFile(path_, "wb"));
  if (file_.get() == nullptr)
    failed_ = true;

  // Allocate the header.
  Position pos = Allocate(sizeof(MINIDUMP_HEADER));
  DCHECK_EQ(kHeaderPos, pos);

  return succeeded();
}

bool MinidumpSerializer::SerializeThreads(
    const std::vector<ThreadSpecification>& specs) {
  if (specs.empty())
    return succeeded();

  std::vector<MINIDUMP_THREAD> threads;
  threads.resize(specs.size());

  for (int i = 0; i < specs.size(); ++i) {
    const ThreadSpecification& spec = specs[i];

    // Write the context.
    DCHECK_EQ(sizeof(CONTEXT), spec.context_data.size());
    Position pos = AppendBytes(spec.context_data);

    // Copy thread to vector for more efficient serialization, then set Rvas.
    DCHECK_EQ(sizeof(MINIDUMP_THREAD), spec.thread_data.size());
    memcpy(&threads.at(i), spec.thread_data.c_str(), sizeof(MINIDUMP_THREAD));

    MINIDUMP_THREAD& thread = threads[i];
    refinery::AddressRange stack_range(thread.Stack.StartOfMemoryRange,
                                       thread.Stack.Memory.DataSize);
    if (!GetPos(stack_range, &thread.Stack.Memory.Rva))
      failed_ = true;
    thread.ThreadContext.Rva = pos;
  }

  AppendListStream(ThreadListStream, threads);
  return succeeded();
}

bool MinidumpSerializer::SerializeMemory(
    const std::vector<MemorySpecification>& regions) {
  // Signal that memory serialization has occured, and regions now have
  // associated positions in the minidump.
  is_serialize_memory_invoked_ = true;

  if (regions.empty())
    return succeeded();

  // Write bytes data and create the memory descriptors.
  std::vector<MINIDUMP_MEMORY_DESCRIPTOR> memory_descriptors;
  memory_descriptors.resize(regions.size());
  size_t idx = 0;
  for (const auto& region : regions) {
    refinery::AddressRange range(region.address, region.buffer.size());
    DCHECK(range.IsValid());

    Position pos = AppendBytes(region.buffer);
    auto inserted = memory_positions_.insert(std::make_pair(range, pos));
    DCHECK_EQ(true, inserted.second);

    memory_descriptors[idx].StartOfMemoryRange = range.start();
    memory_descriptors[idx].Memory.DataSize = range.size();
    memory_descriptors[idx].Memory.Rva = pos;

    ++idx;
  }

  // Write descriptors and create directory entry.
  AppendListStream(MemoryListStream, memory_descriptors);

  return succeeded();
}

bool MinidumpSerializer::SerializeModules(
    const std::vector<ModuleSpecification>& module_specs) {
  if (module_specs.empty())
    return succeeded();

  std::vector<MINIDUMP_MODULE> modules;
  modules.resize(module_specs.size());

  for (int i = 0; i < module_specs.size(); ++i) {
    modules[i].BaseOfImage = module_specs[i].addr;
    modules[i].SizeOfImage = module_specs[i].size;
    modules[i].CheckSum = module_specs[i].checksum;
    modules[i].TimeDateStamp = module_specs[i].timestamp;
    modules[i].ModuleNameRva = AppendMinidumpString(module_specs[i].name);
  }

  AppendListStream(ModuleListStream, modules);

  return succeeded();
}

bool MinidumpSerializer::SerializeExceptions(
    const std::vector<ExceptionSpecification>& exception_specs) {
  if (exception_specs.empty())
    return succeeded();

  for (const ExceptionSpecification& spec : exception_specs) {
    // Write the context.
    DCHECK_EQ(sizeof(CONTEXT), spec.context_data.size());
    Position pos = AppendBytes(spec.context_data);

    // Write the MINIDUMP_EXCEPTION_STREAM.
    ULONG32 thread_id = spec.thread_id;
    Position rva = Append(thread_id);
    ULONG32 dummy_alignment = 0U;
    Append(dummy_alignment);

    MINIDUMP_EXCEPTION exception = {0};
    exception.ExceptionCode = spec.exception_code;
    exception.ExceptionFlags = spec.exception_flags;
    exception.ExceptionRecord = spec.exception_record;
    exception.ExceptionAddress = spec.exception_address;
    exception.NumberParameters = spec.exception_information.size();
    DCHECK(exception.NumberParameters <= EXCEPTION_MAXIMUM_PARAMETERS);
    for (size_t i = 0; i < spec.exception_information.size(); ++i) {
      exception.ExceptionInformation[i] = spec.exception_information[i];
    }
    Append(exception);

    MINIDUMP_LOCATION_DESCRIPTOR context_loc = {};
    context_loc.DataSize = sizeof(CONTEXT);
    context_loc.Rva = pos;
    Append(context_loc);

    AddDirectoryEntry(ExceptionStream, rva, sizeof(MINIDUMP_EXCEPTION_STREAM));
  }

  return succeeded();
}

bool MinidumpSerializer::Finalize() {
  // Serialize the directory.
  Position pos = AppendVec(directory_);

  // Serialize the header.
  MINIDUMP_HEADER hdr;
  hdr.Signature = MINIDUMP_SIGNATURE;
  hdr.NumberOfStreams = directory_.size();
  hdr.StreamDirectoryRva = pos;
  Write(kHeaderPos, hdr);

  return succeeded();
}

MinidumpSerializer::Position MinidumpSerializer::Allocate(size_t size_bytes) {
  Position pos = cursor_;
  if (!IncrementCursor(size_bytes))
    failed_ = true;
  return pos;
}

template <class DataType>
MinidumpSerializer::Position MinidumpSerializer::Append(const DataType& data) {
  Position pos = Allocate(sizeof(data));
  Write(pos, data);
  return pos;
}

template <class DataType>
MinidumpSerializer::Position MinidumpSerializer::AppendVec(
    const std::vector<DataType>& data) {
  DCHECK(!data.empty());

  size_t size_bytes = sizeof(DataType) * data.size();
  Position pos = Allocate(size_bytes);
  WriteBytes(pos, size_bytes, &data.at(0));
  return pos;
}

template <class DataType>
MinidumpSerializer::Position MinidumpSerializer::AppendListStream(
    MINIDUMP_STREAM_TYPE type,
    const std::vector<DataType>& elements) {
  DCHECK(!elements.empty());

  // Append the stream
  ULONG32 num_elements = elements.size();
  Position pos = Append(num_elements);
  AppendVec(elements);

  // Create its directory entry.
  size_t size_bytes = sizeof(ULONG32) + elements.size() * sizeof(DataType);
  AddDirectoryEntry(type, pos, size_bytes);

  return pos;
}

MinidumpSerializer::Position MinidumpSerializer::AppendBytes(
    base::StringPiece data) {
  Position pos = Allocate(data.length());
  WriteBytes(pos, data.length(), data.data());
  return pos;
}

MinidumpSerializer::Position MinidumpSerializer::AppendMinidumpString(
    base::StringPiece utf8) {
  std::wstring wide = base::UTF8ToWide(utf8);
  ULONG32 size_bytes = wide.length() * sizeof(std::wstring::value_type);

  Position pos = Append(size_bytes);
  // Note: write the null termination character.
  size_bytes += sizeof(std::wstring::value_type);
  Position string_pos = Allocate(size_bytes);
  WriteBytes(string_pos, size_bytes, wide.c_str());
  return pos;
}

template <class DataType>
void MinidumpSerializer::Write(Position pos, const DataType& data) {
  WriteBytes(pos, sizeof(data), &data);
}

void MinidumpSerializer::WriteBytes(Position pos,
                                    size_t size_bytes,
                                    const void* data) {
  if (failed_)
    return;

  // Validate the write does not go past the cursor.
  base::CheckedNumeric<Position> pos_end = pos;
  pos_end += size_bytes;
  DCHECK(pos_end.IsValid());
  DCHECK(pos_end.ValueOrDie() <= cursor_);

  DCHECK(file_.get() != nullptr);

  // Seek and write.
  if (fseek(file_.get(), pos, SEEK_SET) != 0) {
    failed_ = true;
    return;
  }
  if (fwrite(data, sizeof(char), size_bytes, file_.get()) != size_bytes) {
    failed_ = true;
    return;
  }
}

bool MinidumpSerializer::IncrementCursor(size_t size_bytes) {
  base::CheckedNumeric<Position> cur = cursor_;
  cur += size_bytes;
  if (!cur.IsValid())
    return false;

  cursor_ += size_bytes;
  return true;
}

bool MinidumpSerializer::GetPos(const refinery::AddressRange& range,
                                Position* pos) const {
  DCHECK(range.IsValid());
  DCHECK(pos != nullptr);
  DCHECK(is_serialize_memory_invoked_);

  auto it = memory_positions_.upper_bound(range);
  if (it == memory_positions_.begin())
    return false;

  // Note: given that memory ranges do not overlap, only the immediate
  // predecessor is a candidate match.
  --it;
  if (it->first.Contains(range)) {
    *pos = it->second;
    return true;
  }

  return false;
}

void MinidumpSerializer::AddDirectoryEntry(MINIDUMP_STREAM_TYPE type,
                                           Position pos,
                                           size_t size_bytes) {
  MINIDUMP_DIRECTORY directory = {0};
  directory.StreamType = type;
  directory.Location.Rva = pos;
  directory.Location.DataSize = size_bytes;
  directory_.push_back(directory);
}

}  // namespace

const uint32_t ScopedMinidump::kMinidumpWithStacks =
    MiniDumpWithProcessThreadData |  // Get PEB and TEB.
    MiniDumpWithUnloadedModules;     // Get unloaded modules when available.

const uint32_t ScopedMinidump::kMinidumpWithData =
    kMinidumpWithStacks |
    MiniDumpWithIndirectlyReferencedMemory;  // Get referenced memory.

MinidumpSpecification::MinidumpSpecification() : allow_memory_overlap_(false) {
}

MinidumpSpecification::MinidumpSpecification(AllowMemoryOverlap dummy)
    : allow_memory_overlap_(true) {
}

bool MinidumpSpecification::AddThread(const ThreadSpecification& spec) {
  DCHECK_EQ(sizeof(MINIDUMP_THREAD), spec.thread_data.size());
  DCHECK_EQ(sizeof(CONTEXT), spec.context_data.size());
  DCHECK_GT(spec.thread_data.size(), 0U);
  DCHECK_GT(spec.context_data.size(), 0U);

  threads_.push_back(spec);

  return true;
}

bool MinidumpSpecification::AddMemoryRegion(const MemorySpecification& spec) {
  refinery::Address address = spec.address;
  refinery::Size size_bytes = spec.buffer.size();

  // Ensure range validity.
  refinery::AddressRange range(address, size_bytes);
  if (!range.IsValid())
    return false;

  if (!allow_memory_overlap_) {
    // Overlap is not allowed in this instance - check with successor and
    // predecessor.
    auto it = region_sizes_.upper_bound(address);

    if (it != region_sizes_.end()) {
      refinery::AddressRange post_range(it->first, it->second);
      DCHECK(post_range.IsValid());
      if (range.Intersects(post_range))
        return false;
    }

    if (it != region_sizes_.begin()) {
      --it;
      refinery::AddressRange pre_range(it->first, it->second);
      DCHECK(pre_range.IsValid());
      if (range.Intersects(pre_range))
        return false;
    }

    // Add the specification.
    auto inserted = region_sizes_.insert(std::make_pair(address, size_bytes));
    if (!inserted.second)
      return false;
  }

  memory_regions_.push_back(spec);

  return true;
}

bool MinidumpSpecification::AddModule(const ModuleSpecification& module) {
  modules_.push_back(module);
  return true;
}

bool MinidumpSpecification::AddException(
    const ExceptionSpecification& exception) {
  exceptions_.push_back(exception);
  return true;
}

bool MinidumpSpecification::Serialize(const base::ScopedTempDir& dir,
                                      base::FilePath* path) const {
  MinidumpSerializer serializer;
  bool success = serializer.Initialize(dir) &&
                 serializer.SerializeMemory(memory_regions_) &&
                 serializer.SerializeThreads(threads_) &&
                 serializer.SerializeModules(modules_) &&
                 serializer.SerializeExceptions(exceptions_) &&
                 serializer.Finalize();
  *path = serializer.path();
  return success;
}

MinidumpSpecification::MemorySpecification::MemorySpecification()
    : address(0ULL) {
}

MinidumpSpecification::MemorySpecification::MemorySpecification(
    refinery::Address addr,
    base::StringPiece data)
    : address(addr) {
  data.CopyToString(&buffer);
}

MinidumpSpecification::ThreadSpecification::ThreadSpecification(
    size_t thread_id,
    refinery::Address stack_address,
    refinery::Size stack_size) {
  // Generate the MINIDUMP_THREAD.
  thread_data.resize(sizeof(MINIDUMP_THREAD));
  MINIDUMP_THREAD* thread =
      reinterpret_cast<MINIDUMP_THREAD*>(&thread_data.at(0));
  thread->ThreadId = thread_id;
  thread->SuspendCount = 2;
  thread->PriorityClass = 3;
  thread->Priority = 4;
  thread->Teb = 5U;
  thread->Stack.StartOfMemoryRange = stack_address;
  thread->Stack.Memory.DataSize = stack_size;
  thread->ThreadContext.DataSize = sizeof(CONTEXT);
  // Note: thread.Stack.Memory.Rva and thread.ThreadContext.Rva are set during
  // serialization.

  PopulateContext(&context_data, 0);
}

void MinidumpSpecification::ThreadSpecification::SetTebAddress(
    refinery::Address addr) {
  DCHECK(thread_data.size() == sizeof(MINIDUMP_THREAD));
  MINIDUMP_THREAD* thread =
      reinterpret_cast<MINIDUMP_THREAD*>(&thread_data.at(0));
  thread->Teb = addr;
}

void MinidumpSpecification::ThreadSpecification::FillStackMemorySpecification(
    MinidumpSpecification::MemorySpecification* spec) const {
  DCHECK(spec);
  DCHECK_EQ(sizeof(MINIDUMP_THREAD), thread_data.size());
  const MINIDUMP_THREAD* thread =
      reinterpret_cast<const MINIDUMP_THREAD*>(&thread_data.at(0));

  // The stack is a range of 'S' padded at either end with a single 'P'.
  DCHECK_GT(thread->Stack.StartOfMemoryRange, 0U);
  const ULONG32 kStackMaxSize = static_cast<ULONG32>(-1) - 1;
  DCHECK(thread->Stack.Memory.DataSize < kStackMaxSize);
  spec->address = thread->Stack.StartOfMemoryRange - 1;
  spec->buffer.resize(thread->Stack.Memory.DataSize + 2, 'S');
  spec->buffer[0] = 'P';
  spec->buffer[thread->Stack.Memory.DataSize + 1] = 'P';
}

MinidumpSpecification::ExceptionSpecification::ExceptionSpecification(
    uint32_t thread_identifier) {
  thread_id = thread_identifier;
  exception_code = EXCEPTION_ACCESS_VIOLATION;
  exception_flags = EXCEPTION_NONCONTINUABLE;
  exception_record = 0ULL;
  exception_address = 1111ULL;
  exception_information.push_back(1);
  exception_information.push_back(2222ULL);

  PopulateContext(&context_data, 100);
}

MinidumpSpecification::ModuleSpecification::ModuleSpecification() {
  addr = 12345ULL;
  size = 75U;
  checksum = 23U;
  timestamp = 42U;
  name = "someModule";
}

namespace {

// Minidump.
const wchar_t kMinidumpFileName[] = L"minidump.dmp";
const char kSwitchExceptionPtrs[] = "exception-ptrs";
const char kSwitchPid[] = "dump-pid";
const char kSwitchMinidumpPath[] = "dump-path";
const char kSwitchTid[] = "exception-thread-id";
const char kSwitchMinidumpType[] = "minidump-type";

__declspec(noinline) DWORD GetEip() {
  return reinterpret_cast<DWORD>(_ReturnAddress());
}

}  // namespace

MULTIPROCESS_TEST_MAIN(MinidumpDumperProcess) {
  // Retrieve information from the command line.
  base::CommandLine* cmd_line = base::CommandLine::ForCurrentProcess();
  if (!cmd_line->HasSwitch(kSwitchPid) || !cmd_line->HasSwitch(kSwitchTid) ||
      !cmd_line->HasSwitch(kSwitchExceptionPtrs) ||
      !cmd_line->HasSwitch(kSwitchMinidumpPath)) {
    return 1;
  }

  std::string pid_string = cmd_line->GetSwitchValueASCII(kSwitchPid);
  unsigned pid_uint = 0U;
  if (!base::StringToUint(pid_string, &pid_uint))
    return 1;
  base::ProcessId pid = static_cast<base::ProcessId>(pid_uint);

  std::string thread_id_string = cmd_line->GetSwitchValueASCII(kSwitchTid);
  unsigned thread_id = 0U;
  if (!base::StringToUint(thread_id_string, &thread_id))
    return 1;

  std::string exception_ptrs_string =
      cmd_line->GetSwitchValueASCII(kSwitchExceptionPtrs);
  unsigned exception_ptrs = 0ULL;
  if (!base::StringToUint(exception_ptrs_string, &exception_ptrs))
    return 1;
  std::string minidump_type_string =
      cmd_line->GetSwitchValueASCII(kSwitchMinidumpType);
  uint32_t minidump_type = 0U;
  if (!base::StringToUint(minidump_type_string, &minidump_type))
    return 1;

  base::FilePath minidump_path =
      cmd_line->GetSwitchValuePath(kSwitchMinidumpPath);

  // Get handles to dumpee and dump file.
  base::Process dumpee_process = base::Process::OpenWithAccess(
      pid, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ);
  if (!dumpee_process.IsValid()) {
    LOG(ERROR) << "Failed to open process: " << ::common::LogWe() << ".";
    return 1;
  }

  base::File minidump_file(minidump_path,
                           base::File::FLAG_CREATE | base::File::FLAG_WRITE);
  if (!minidump_file.IsValid()) {
    LOG(ERROR) << "Failed to create minidump file: " << minidump_path.value();
    return 1;
  }

  // Build the dump related information.
  MINIDUMP_EXCEPTION_INFORMATION exception_information = {};
  exception_information.ThreadId = static_cast<DWORD>(thread_id);
  exception_information.ExceptionPointers =
      reinterpret_cast<PEXCEPTION_POINTERS>(exception_ptrs);
  exception_information.ClientPointers = true;

  MINIDUMP_USER_STREAM_INFORMATION* user_info = nullptr;
  MINIDUMP_CALLBACK_INFORMATION* callback_info = nullptr;

  // Take the minidump.
  if (::MiniDumpWriteDump(
          dumpee_process.Handle(), pid, minidump_file.GetPlatformFile(),
          static_cast<MINIDUMP_TYPE>(minidump_type), &exception_information,
          user_info, callback_info) == FALSE) {
    LOG(ERROR) << "MiniDumpWriteDump failed: " << ::common::LogWe() << ".";
    return 1;
  }

  return 0;
}

bool ScopedMinidump::GenerateMinidump(uint32_t minidump_type) {
  // Determine minidump path.
  if (!temp_dir_.CreateUniqueTempDir())
    return false;

  minidump_path_ = temp_dir_.path().Append(kMinidumpFileName);

  // Grab a context. RtlCaptureContext sets the instruction pointer, stack
  // pointer and base pointer to values from this function's callee (similar
  // to _ReturnAddress). Override them so they actually match the context.
  // TODO(manzagop): package this to a utility function.
  CONTEXT context = {};
  ::RtlCaptureContext(&context);
  __asm {
    mov context.Ebp, ebp
    mov context.Esp, esp
  }
  context.Eip = GetEip();

  // Build the exception information.
  EXCEPTION_RECORD exception = {};
  exception.ExceptionCode = 0xCAFEBABE;  // Note: a random error code.
  exception.ExceptionAddress = reinterpret_cast<PVOID>(context.Eip);

  EXCEPTION_POINTERS exception_pointers = {&exception, &context};

  // Build the dumper's command line.
  base::CommandLine dumper_command_line(
      base::GetMultiProcessTestChildBaseCommandLine());
  dumper_command_line.AppendSwitchASCII(switches::kTestChildProcess,
                                        "MinidumpDumperProcess");
  base::Process current_process = base::Process::Current();
  dumper_command_line.AppendSwitchASCII(
      kSwitchPid, base::UintToString(current_process.Pid()));
  dumper_command_line.AppendSwitchASCII(
      kSwitchTid, base::UintToString(::GetCurrentThreadId()));
  unsigned exception_pointers_uint =
      reinterpret_cast<unsigned>(&exception_pointers);
  dumper_command_line.AppendSwitchASCII(
      kSwitchExceptionPtrs, base::UintToString(exception_pointers_uint));
  dumper_command_line.AppendSwitchASCII(kSwitchMinidumpType,
                                        base::UintToString(minidump_type));
  dumper_command_line.AppendSwitchPath(kSwitchMinidumpPath, minidump_path());

  // Launch the dumper.
  base::Process dumper_process =
      base::LaunchProcess(dumper_command_line, base::LaunchOptions());
  int exit_code = 0;
  bool success = dumper_process.WaitForExitWithTimeout(
      TestTimeouts::action_timeout(), &exit_code);
  if (!success) {
    dumper_process.Terminate(0, true);
    return false;
  }

  return exit_code == 0;
}

ScopedHeap::ScopedHeap() : heap_(nullptr) {
}

ScopedHeap::~ScopedHeap() {
  if (heap_ != nullptr) {
    EXPECT_TRUE(::HeapDestroy(heap_));
    heap_ = nullptr;
  }
}

bool ScopedHeap::Create() {
  CHECK(heap_ == nullptr);
  heap_ = ::HeapCreate(0, 0, 0);
  return heap_ != nullptr;
}

void* ScopedHeap::Allocate(size_t block_size) {
  CHECK(heap_ != nullptr);

  return ::HeapAlloc(heap_, 0, block_size);
}

bool ScopedHeap::Free(void* block) {
  CHECK(heap_ != nullptr);

  return ::HeapFree(heap_, 0, block);
}

bool ScopedHeap::IsLFHBlock(const void* block) {
  const uint32_t* ptr = reinterpret_cast<const uint32_t*>(block);
  __try {
    // Search back a bounded distance for the LFH bin signature.
    for (size_t i = 0; i < 32; ++i) {
      const uint32_t kLFHBinSignature = 0xF0E0D0C0;
      if (*ptr-- == kLFHBinSignature)
        return true;
    }
  } __except (EXCEPTION_EXECUTE_HANDLER) {  // NOLINT
    // Note that git cl format yields the above, which is then contrary to
    // our presubmit checks.
    // On exception, we conclude this isn't an LFH block.
  }

  return false;
}

refinery::Address ToAddress(const void* ptr) {
  return static_cast<refinery::Address>(reinterpret_cast<uintptr_t>(ptr));
}

bool IsAppVerifierActive() {
  // TODO(siggi): This seems like a solid proxy for verifier present.
  return ::GetModuleHandle(L"verifier.dll") != nullptr;
}

}  // namespace testing

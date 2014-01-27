// Copyright 2013 Google Inc. All Rights Reserved.
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

#include "syzygy/sampler/sampler_app.h"

#include <psapi.h>

#include "base/bind.h"
#include "base/file_util.h"
#include "base/stringprintf.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_split.h"
#include "syzygy/common/align.h"
#include "syzygy/common/buffer_writer.h"
#include "syzygy/pe/pe_file.h"
#include "syzygy/trace/common/clock.h"
#include "syzygy/trace/protocol/call_trace_defs.h"
#include "syzygy/trace/service/trace_file_writer.h"

namespace sampler {

namespace {

typedef trace::service::TraceFileWriter TraceFileWriter;

const char kUsageFormatStr[] =
    "Usage: %ls [options] MODULE_PATH1 [MODULE_PATH2 ...]\n"
    "\n"
    "  A tool that polls running processes and profiles modules of interest.\n"
    "\n"
    "  The tool works by monitoring running processes. Any process that gets\n"
    "  through the optional PID filter will be inspected, and if any of the\n"
    "  specified modules are loaded in that process they will be profiled.\n"
    "\n"
    "Options:\n"
    "\n"
    "  --blacklist-pids      If a list of PIDs is specified with --pids, this\n"
    "                        makes the list a blacklist of processes not to\n"
    "                        be monitored. Defaults to false, in which case\n"
    "                        the list is a whitelist.\n"
    "  --bucket-size=POSINT  Specifies the bucket size. This must be a power\n"
    "                        of two, and must be >= 4. Defaults to 4.\n"
    "  --output-dir=DIR      The path to write trace-files. Will be created\n"
    "                        if it doesn't exist. Defaults to the current\n"
    "                        working directory.\n"
    "  --pids=PID1,PID2,...  Specifies a list of PIDs. If specified these are\n"
    "                        used as a filter (by default a whitelist) for\n"
    "                        processes to be profiled. If not specified all\n"
    "                        processes will be potentially profiled.\n"
    "  --sampling-interval=INTERVAL\n"
    "                        Sets the sampling interval. This is a floating\n"
    "                        point value in seconds. Scientific notation is\n"
    "                        acceptable. Defaults to the current system\n"
    "                        setting. Not all sampling intervals are\n"
    "                        available on all systems so the closest value\n"
    "                        available will be used. The actual sampling\n"
    "                        interval used will be reported.\n"
    "  --output-dir=DIR      Specifies the output directory into which trace\n"
    "                        files will be written.\n"
    "\n";

// Parses the bucket size. Leaves the value unchanged if it is not specified.
bool ParseBucketSize(const CommandLine* command_line,
                     size_t* log2_bucket_size) {
  DCHECK(command_line != NULL);
  DCHECK(log2_bucket_size != NULL);

  if (!command_line->HasSwitch(SamplerApp::kBucketSize))
    return true;

  std::string s = command_line->GetSwitchValueASCII(SamplerApp::kBucketSize);
  size_t bucket_size = 0;
  if (!base::StringToSizeT(s, &bucket_size)) {
    LOG(ERROR) << "--" << SamplerApp::kBucketSize << " must be an integer.";
    return false;
  }
  if (!common::IsPowerOfTwo(bucket_size)) {
    LOG(ERROR) << "--" << SamplerApp::kBucketSize << " must be a power of 2.";
    return false;
  }
  if (bucket_size < 4) {
    LOG(ERROR) << "--" << SamplerApp::kBucketSize << " must be >= 4.";
    return false;
  }

  // Convert to a power of two, as required by the SamplingProfiler API.
  *log2_bucket_size = 2;
  while (bucket_size != 4) {
    bucket_size >>= 1;
    ++(*log2_bucket_size);
  }

  return true;
}

// Parses the sampling interval. Leaves the value unchanged if it is not
// specified.
bool ParseSamplingInterval(const CommandLine* command_line,
                           base::TimeDelta* sampling_interval) {
  DCHECK(command_line != NULL);
  DCHECK(sampling_interval != NULL);

  if (!command_line->HasSwitch(SamplerApp::kSamplingInterval))
    return true;

  std::string s = command_line->GetSwitchValueASCII(
      SamplerApp::kSamplingInterval);
  double d = 0;
  if (!base::StringToDouble(s, &d)) {
    LOG(ERROR) << "--" << SamplerApp::kSamplingInterval << " must be a double.";
    return false;
  }
  if (d <= 0) {
    LOG(ERROR) << "-- " << SamplerApp::kSamplingInterval
               << " must be positive.";
    return false;
  }

  int64 us = static_cast<int64>(1000000 * d);
  if (us <= 0) {
    LOG(ERROR) << "--" << SamplerApp::kSamplingInterval
               << " must be at least 1us.";
    return false;
  }

  // TimeDelta has its finest resolution in microseconds, so we convert to
  // that.
  *sampling_interval = base::TimeDelta::FromMicroseconds(us);
  return true;
}

// A utility function for converting a time delta to a human readable string.
const std::string TimeDeltaToString(const base::TimeDelta& td) {
  // Aliases to constants from base::Time (which have overly long names).
  const int64& kMillisecond = base::Time::kMicrosecondsPerMillisecond;
  const int64& kSecond = base::Time::kMicrosecondsPerSecond;
  const int64& kMinute = base::Time::kMicrosecondsPerMinute;
  const int64& kHour = base::Time::kMicrosecondsPerHour;
  const int64& kDay = base::Time::kMicrosecondsPerDay;
  int64 us = td.InMicroseconds();

  if (us == 0)
    return "0s";

  bool negative = us < 0;
  if (negative)
    us *= -1;

  std::string s;
  if (negative)
    s = "-";

  // Special case: We're less than a second.
  if (us < kSecond) {
    // We're in the hundreds of milliseconds.
    if (us >= 100 * kMillisecond) {
      s.append(base::StringPrintf("%.6fs", static_cast<double>(us) / kSecond));
    } else if (us >= kMillisecond) {
      // We're in the milliseconds.
      s.append(base::StringPrintf("%.3fms",
                                  static_cast<double>(us) / kMillisecond));
    } else {
      // We're in microseconds.
      s.append(base::StringPrintf("%lldus", us));
    }
    return s;
  }

  int64 days = us / kDay;
  int64 hours = (us % kDay) / kHour;
  int64 minutes = (us % kHour) / kMinute;
  int64 seconds = (us % kMinute) / kSecond;
  us %= kSecond;

  if (days > 0)
    s.append(base::StringPrintf("%lldd", days));
  if (hours > 0)
    s.append(base::StringPrintf("%lldh", hours));
  if (minutes > 0)
    s.append(base::StringPrintf("%lldm", minutes));
  if (seconds > 0 || us > 0)
    s.append(base::StringPrintf("%lld.%06llds", seconds, us));

  return s;
}

// Sets the sampling interval used across all sampling profilers.
bool SetSamplingInterval(base::TimeDelta* sampling_interval) {
  bool use_system_default = sampling_interval->ToInternalValue() == 0;

  if (!use_system_default) {
    // Set the sampling interval.
    if (!SamplingProfiler::SetSamplingInterval(*sampling_interval)) {
      LOG(ERROR) << "SetSamplingInterval failed.";
      return false;
    }
  }

  // Get the actual sampling interval.
  base::TimeDelta actual_sampling_interval;
  if (!SamplingProfiler::GetSamplingInterval(&actual_sampling_interval)) {
    LOG(ERROR) << "GetSamplingInterval failed.";
    return false;
  }

  if (use_system_default) {
    // If we're using the system default then report it.
    LOG(INFO) << "Using system default sampling interval of "
              << TimeDeltaToString(actual_sampling_interval) << ".";
  } else {
    // If the actual sampling interval and the requested one don't match, then
    // output a warning.
    if (actual_sampling_interval != *sampling_interval) {
      LOG(WARNING) << "Requested sampling interval of "
                   << TimeDeltaToString(*sampling_interval)
                   << " but actual sampling interval is "
                   << TimeDeltaToString(actual_sampling_interval) << ".";
    }
  }

  *sampling_interval = actual_sampling_interval;

  return true;
}

// Populates a vector of active process IDs on the system. By the time has
// returned some of the PIDs may no longer be active, and others may have
// started. Returns true on success, false otherwise.
typedef std::vector<DWORD> PidVector;
bool GetRunningProcessIds(PidVector* pids) {
  DCHECK(pids != NULL);

  // Start with a fairly large size.
  pids->resize(512);
  while (true) {
    DWORD bytes_avail = pids->size() * sizeof(PidVector::value_type);
    DWORD bytes_used = 0;
    BOOL result = ::EnumProcesses(&((*pids)[0]), bytes_avail, &bytes_used);
    if (!result) {
      DWORD error = ::GetLastError();
      LOG(ERROR) << "EnumProcess failed: " << common::LogWe(error);
      return false;
    }

    // We know that we've finished reading the list if the system call didn't
    // use the entire available buffer. Shrink it back down to minimum size
    // and return it.
    if (bytes_used < bytes_avail) {
      size_t pid_count = bytes_used / sizeof(PidVector::value_type);
      pids->resize(pid_count);
      return true;
    }

    // Making it to this point means there wasn't enough room for all of the
    // PIDs. Grow bigger and try again.
    pids->resize(pids->size() * 2);
  }
}

// Opens the given process. If the process no longer exists or if access is
// denied this returns true but sets @p process to NULL. If it fails for any
// other reason this returns false. Upon success @p process will be set to the
// process handle (which must be closed by the caller) and returns true.
bool GetProcessHandle(DWORD pid, HANDLE* process) {
  DCHECK(process != NULL);

  // Get a handle to the process.
  const DWORD kDesiredAccess = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ;
  *process = ::OpenProcess(kDesiredAccess, FALSE /* inherit_handle */, pid);
  if (*process != NULL)
    return true;

  DWORD error = ::GetLastError();

  // If access is denied this is not an unexpected failure and we simply
  // return an empty module list. If the PID is not valid (the process has
  // since shut down) we can also safely ignore failure.
  if (error == ERROR_ACCESS_DENIED || error == ERROR_INVALID_PARAMETER)
    return true;

  // Getting here means we were unable to open a handle to the process.
  LOG(ERROR) << "OpenProcess failed: " << common::LogWe(error);
  return false;
}

// Populates a vector of module handles for the given process. By the time this
// call has returned some modules may no longer be in memory and others may
// have been loaded. If the process is unable to be read because it is 64-bit
// then this will return an empty module list. Returns true on success, false
// otherwise.
typedef std::vector<HMODULE> HmoduleVector;
bool GetProcessModules(HANDLE process, HmoduleVector* modules) {
  DCHECK(process != NULL);
  DCHECK(modules != NULL);

  modules->resize(32);
  while (true) {
    DWORD bytes_avail = modules->size() * sizeof(HmoduleVector::value_type);
    DWORD bytes_used = 0;
    if (!::EnumProcessModules(process, &modules->at(0),
                              bytes_avail, &bytes_used)) {
      DWORD error = ::GetLastError();

      // Trying to enumerate the modules of a 64-bit process from this 32-bit
      // process is not possible. We simply return an empty module list.
      if (error == ERROR_PARTIAL_COPY) {
        modules->clear();
        return true;
      }

      LOG(ERROR) << "EnumProcessModules failed: " << common::LogWe(error);
      return false;
    }

    // We know that we've finished reading the list if the system call didn't
    // use the entire available buffer. Shrink it back down to minimum size
    // and return it.
    if (bytes_used < bytes_avail) {
      size_t module_count = bytes_used / sizeof(HmoduleVector::value_type);
      modules->resize(module_count);
      return true;
    }

    // Making it to this point means that there wasn't enough room for all of
    // the modules. Grow bigger and try again.
    modules->resize(modules->size() * 2);
  }

  return true;
}

// Gets the signature of the given loaded module. Returns true on success,
// false otherwise.
bool GetModuleSignature(HANDLE process,
                        HMODULE module,
                        SamplerApp::ModuleSignature* module_sig) {
  DCHECK(process != NULL);
  DCHECK(module != NULL);
  DCHECK(module_sig != NULL);

  uint8 buffer[4096] = {};
  COMPILE_ASSERT(
      sizeof(buffer) >= sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS),
      buffer_must_be_at_least_as_big_as_headers);

  // Read the first page of the module from the remote process. We use
  // this to get the module headers so we can grab its signature.
  SIZE_T bytes_read = 0;
  if (!::ReadProcessMemory(process, module, buffer, sizeof(buffer),
                           &bytes_read)) {
    DWORD error = ::GetLastError();
    LOG(ERROR) << "ReadProcessMemory failed: " << common::LogWe(error);
    return false;
  }
  if (bytes_read != sizeof(buffer)) {
    LOG(ERROR) << "ReadProcessMemory only performed a partial read.";
    return false;
  }

  // Get the DOS header and make sure the NT headers are contained entirely in
  // the buffer.
  const IMAGE_DOS_HEADER* dos_header =
      reinterpret_cast<const IMAGE_DOS_HEADER*>(buffer);
  if (dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS) > sizeof(buffer)) {
    LOG(ERROR) << "NT headers not contained in buffer.";
    return false;
  }

  // Grab the NT headers.
  const IMAGE_NT_HEADERS* nt_headers =
      reinterpret_cast<const IMAGE_NT_HEADERS*>(buffer + dos_header->e_lfanew);

  // Extract the signature.
  module_sig->checksum = nt_headers->OptionalHeader.CheckSum;
  module_sig->size = nt_headers->OptionalHeader.SizeOfImage;
  module_sig->time_date_stamp = nt_headers->FileHeader.TimeDateStamp;

  return true;
}

typedef base::Callback<void (const SampledModuleCache::Module*)>
    StartProfilingCallback;

// Attaches to the running process with the specified PID and iterates over
// its modules. If any of them is found in the list of modules to be profiled
// adds the process/module pair to the sample module cache.
bool InspectProcessModules(DWORD pid,
                           SamplerApp::ModuleSignatureSet& module_sigs,
                           StartProfilingCallback callback,
                           SampledModuleCache* cache) {
  DCHECK(!callback.is_null());
  DCHECK(cache != NULL);

  base::win::ScopedHandle handle;
  if (!GetProcessHandle(pid, handle.Receive()))
    return false;

  // GetProcessHandle can succeed but return no handle. In this case the
  // process has since exited.
  if (!handle.IsValid())
    return true;

  // Get a list of modules in the process.
  HmoduleVector modules;
  if (!GetProcessModules(handle.Get(), &modules))
    return false;

  // Iterate over the modules in the process.
  for (size_t i = 0; i < modules.size(); ++i) {
    SamplerApp::ModuleSignature module_sig = {};
    if (!GetModuleSignature(handle.Get(), modules[i], &module_sig))
      return false;

    // Skip over this module if its not in the set of modules of interest.
    if (module_sigs.find(module_sig) == module_sigs.end())
      continue;

    // Add this module to the list of those being profiled.
    SampledModuleCache::ProfilingStatus status =
        SampledModuleCache::kProfilingStarted;
    const SampledModuleCache::Module* module = NULL;
    if (!cache->AddModule(handle.Get(), modules[i], &status, &module))
      return false;

    // If this module was just added for the first time then invoke the
    // testing seam callback.
    if (status == SampledModuleCache::kProfilingStarted)
      callback.Run(module);
  }

  return true;
}

// Writes a trace data object to a trace file, preceding it with a record
// prefix and trace-file segment header as necessary.
template<typename TraceDataType>
bool WriteTraceRecord(const TraceDataType* trace_data,
                      size_t size,
                      TraceEventType data_type,
                      TraceFileWriter* writer) {
  DCHECK(writer != NULL);

  std::vector<uint8> buffer;
  common::VectorBufferWriter w(&buffer);

  // Write the record prefix for the segment header.
  RecordPrefix record = {};
  record.timestamp = trace::common::GetTsc();
  record.size = sizeof(TraceFileSegmentHeader);
  record.type = TraceFileSegmentHeader::kTypeId;
  record.version.hi = TRACE_VERSION_HI;
  record.version.lo = TRACE_VERSION_LO;
  if (!w.Write(record))
    return false;

  // Write the segment header.
  TraceFileSegmentHeader segment = {};
  segment.thread_id = 0;
  segment.segment_length = sizeof(RecordPrefix) + size;
  if (!w.Write(segment))
    return false;

  // Now write a record-prefix for the actual data.
  record.size = size;
  record.type = data_type;
  if (!w.Write(record))
    return false;

  // Write the actual data.
  if (!w.Write(size, reinterpret_cast<const void*>(trace_data)))
    return false;

  // Align the output to the block size.
  if (!w.Align(writer->block_size()))
    return false;

  // Write the whole chunk of data.
  if (!writer->WriteRecord(buffer.data(), buffer.size()))
    return false;

  return true;
}

// Output a TRACE_PROCESS_ATTACH_EVENT for |module|. This allows the grinder
// to tie subsequent sample data to a module on disk.
bool WriteTraceModuleDataRecord(const SampledModuleCache::Module* module,
                                TraceFileWriter* writer) {
  DCHECK(module != NULL);
  DCHECK(writer != NULL);

  TraceModuleData module_data = {};
  module_data.module_base_addr = reinterpret_cast<ModuleAddr>(module->module());
  module_data.module_base_size = module->module_size();
  module_data.module_checksum = module->module_checksum();
  module_data.module_time_date_stamp = module->module_time_date_stamp();

  base::FilePath basename = module->module_path().BaseName();
  ::wcsncpy(module_data.module_name, basename.value().c_str(),
            arraysize(module_data.module_name) - 1);

  ::wcsncpy(module_data.module_exe, module->module_path().value().c_str(),
            arraysize(module_data.module_exe) - 1);

  // We simulate a 'process attached to module' event. The sampling is across
  // all threads in a process, so we can't actually tie the data to any
  // particular thread.
  if (!WriteTraceRecord(&module_data, sizeof(module_data),
                        TRACE_PROCESS_ATTACH_EVENT, writer)) {
    return false;
  }

  return true;
}

// Converts the sample data in |module| to a TraceSampleData buffer and outputs
// it to the provided TraceFileWriter.
bool WriteTraceSampleDataRecord(uint64 sampling_interval_in_cycles,
                                const SampledModuleCache::Module* module,
                                TraceFileWriter* writer) {
  DCHECK(module != NULL);
  DCHECK(writer != NULL);

  const ULONG* buckets = module->profiler().buckets().data();
  size_t bucket_count = module->profiler().buckets().size();
  DCHECK_LT(0u, bucket_count);

  // Calculate the size of the buffer required to store the samples.
  size_t size = offsetof(TraceSampleData, buckets) +
      sizeof(buckets[0]) * bucket_count;

  std::vector<uint8> buffer(size);
  TraceSampleData* data = reinterpret_cast<TraceSampleData*>(buffer.data());

  COMPILE_ASSERT(sizeof(buckets[0]) == sizeof(data->buckets[0]),
                 buckets_have_mismatched_sizes);

  // Populate the TraceSampleData structure.
  data->module_base_addr = reinterpret_cast<ModuleAddr>(module->module());
  data->module_size = module->module_size();
  data->module_checksum = module->module_checksum();
  data->module_time_date_stamp = module->module_time_date_stamp();
  data->bucket_size = 1 << module->log2_bucket_size();
  data->bucket_start = reinterpret_cast<ModuleAddr>(module->buckets_begin());
  data->bucket_count = bucket_count;
  data->sampling_start_time = module->profiling_start_time();
  data->sampling_end_time = module->profiling_stop_time();
  data->sampling_interval = sampling_interval_in_cycles;

  // Copy the samples into the buffer.
  ::memcpy(data->buckets, buckets, sizeof(buckets[0]) * bucket_count);

  if (!WriteTraceRecord(data, size, TRACE_SAMPLE_DATA, writer))
    return false;

  return true;
}

}  // namespace

const char SamplerApp::kBlacklistPids[] = "blacklist-pids";
const char SamplerApp::kBucketSize[] = "bucket-size";
const char SamplerApp::kPids[] = "pids";
const char SamplerApp::kSamplingInterval[] = "sampling-interval";
const char SamplerApp::kOutputDir[] = "output-dir";

const size_t SamplerApp::kDefaultLog2BucketSize = 2;

base::Lock SamplerApp::console_ctrl_lock_;
SamplerApp* SamplerApp::console_ctrl_owner_ = NULL;

SamplerApp::SamplerApp()
    : common::AppImplBase("Sampler"),
      blacklist_pids_(true),
      log2_bucket_size_(kDefaultLog2BucketSize),
      sampling_interval_(),
      running_(true),
      sampling_interval_in_cycles_(0) {
}

SamplerApp::~SamplerApp() {
}

bool SamplerApp::ParseCommandLine(const CommandLine* command_line) {
  DCHECK(command_line != NULL);

  if (command_line->HasSwitch("help"))
    return PrintUsage(command_line->GetProgram(), "");

  // Parse the profiler parameters.
  if (!ParseBucketSize(command_line, &log2_bucket_size_) ||
      !ParseSamplingInterval(command_line, &sampling_interval_)) {
    return PrintUsage(command_line->GetProgram(), "");
  }

  // By default we set up an empty PID blacklist. This means that all PIDs
  // will be profiled.
  if (command_line->HasSwitch(kPids)) {
    // If PIDs have been specified then parse them.
    if (!ParsePids(command_line->GetSwitchValueASCII(kPids)))
      return PrintUsage(command_line->GetProgram(), "");

    blacklist_pids_ = command_line->HasSwitch(kBlacklistPids);
  }

  output_dir_ = command_line->GetSwitchValuePath(kOutputDir);

  const CommandLine::StringVector& args = command_line->GetArgs();
  if (args.size() == 0) {
    return PrintUsage(command_line->GetProgram(),
                      "Must specify at least one module to profile.");
  }

  // Parse the list of modules to profile.
  for (size_t i = 0; i < args.size(); ++i) {
    ModuleSignature sig = {};
    if (!GetModuleSignature(base::FilePath(args[i]), &sig))
      return PrintUsage(command_line->GetProgram(), "");
    module_sigs_.insert(sig);
  }

  return true;
}

int SamplerApp::Run() {
  // Grab the console control if we can.
  {
    base::AutoLock auto_lock(console_ctrl_lock_);
    if (console_ctrl_owner_ == NULL) {
      if (!::SetConsoleCtrlHandler(&OnConsoleCtrl, TRUE)) {
        DWORD error = ::GetLastError();
        LOG(ERROR) << "SetConsoleCtrlHandler failed: " << common::LogWe(error);
        return false;
      }
      console_ctrl_owner_ = this;
    }
  }

  int i = RunImpl();

  // Clean up the console control hook if we own it.
  {
    base::AutoLock auto_lock(console_ctrl_lock_);
    if (console_ctrl_owner_ == this) {
      if (!::SetConsoleCtrlHandler(&OnConsoleCtrl, FALSE)) {
        DWORD error = ::GetLastError();
        LOG(ERROR) << "SetConsoleCtrlHandler failed: " << common::LogWe(error);
        return false;
      }
      console_ctrl_owner_ = NULL;
    }
  }

  return i;
}

int SamplerApp::RunImpl() {
  // Ensure the output directory exists.
  if (!output_dir_.empty()) {
    if (!file_util::PathExists(output_dir_)) {
      LOG(INFO) << "Creating output directory \"" << output_dir_.value()
                << "\".";
    }
    if (!file_util::CreateDirectory(output_dir_)) {
      LOG(ERROR) << "Failed to create output directory \""
                 << output_dir_.value() << "\".";
      return false;
    }
  }

  if (!SetSamplingInterval(&sampling_interval_))
    return 1;

  // TODO(chrisha): Output the clock information to the trace file. This should
  //     be part of the header!

  // Get the system clock information and calculate our sampling interval in
  // system clock cycles.
  trace::common::ClockInfo clock_info = {};
  trace::common::GetClockInfo(&clock_info);
  double interval_in_seconds = sampling_interval_.InSecondsF();
  sampling_interval_in_cycles_ =
      interval_in_seconds * clock_info.tsc_info.frequency;

  SampledModuleCache cache(log2_bucket_size_);
  cache.set_dead_module_callback(
      base::Bind(&SamplerApp::OnDeadModule, base::Unretained(this)));

  // These are used for keeping track of how many modules are being profiled.
  size_t process_count = 0;
  size_t module_count = 0;

  // Sit in a loop, actively monitoring running processes.
  while (running()) {
    // Mark all profiling module as dead. If they aren't remarked as alive after
    // iterating through processes and modules then they will be reaped and
    // their profile data written to disk.
    cache.MarkAllModulesDead();

    PidVector pids;
    if (!GetRunningProcessIds(&pids))
      return 1;

    // Those PIDs in the pids_ filter that aren't seen at all in the list of
    // running processes have to be removed so that they aren't re-filtered if
    // that PID is reused again. We keep track of the PIDs that have been seen
    // in every iteration here.
    PidSet filtered_pids;

    // Iterate over the processes.
    for (size_t i = 0; i < pids.size(); ++i) {
      DWORD pid = pids[i];

      if (blacklist_pids_) {
        // We have a blacklist filter. Skip this process if it is in the
        // blacklist.
        if (pids_.find(pid) != pids_.end()) {
          filtered_pids.insert(pid);
          continue;
        }
      } else {
        // If our PID filter is empty then we have no more work to do, so
        // we can skip out this loop.
        if (pids_.empty()) {
          LOG(INFO) << "Whitelist is empty, no more work to do.";
          set_running(false);
          continue;
        }

        // We have a whitelist filter. Skip this process if it isn't in the
        // whitelist.
        if (pids_.find(pid) == pids_.end()) {
          continue;
        } else {
          filtered_pids.insert(pid);
        }
      }

      // If we get here the process corresponding to this PID needs to be
      // examined.
      StartProfilingCallback callback = base::Bind(
          &SamplerApp::OnStartProfiling, base::Unretained(this));
      if (!InspectProcessModules(pid, module_sigs_, callback, &cache))
        return 1;
    }

    // Remove any profiled modules that are 'dead'. This invokes the callback
    // and causes the profile information to be written to a trace file.
    cache.RemoveDeadModules();

    // Count the number of actively profiled modules and processes.
    size_t new_process_count = cache.processes().size();
    size_t new_module_count = cache.module_count();

    // Output some quick statistics.
    if (process_count != new_process_count ||
        module_count != new_module_count) {
      process_count = new_process_count;
      module_count = new_module_count;
      LOG(INFO) << "Profiling " << module_count << " module"
                << (module_count != 1 ? "s" : "") << " across "
                << process_count << " process"
                << (process_count != 1 ? "es" : "") << ".";
    }

    // Update our list of filtered PIDs.
    pids_ = filtered_pids;

    // We poll every second so as not to consume too much CPU time, but to not
    // get caught too easily by PID reuse.
    ::Sleep(1000);
  }

  // Mark all modules as dead and remove them. This will clean up any in
  // progress profiling data.
  cache.MarkAllModulesDead();
  cache.RemoveDeadModules();

  return 0;
}

bool SamplerApp::PrintUsage(const base::FilePath& program,
                            const base::StringPiece& message) {
  if (!message.empty()) {
    ::fwrite(message.data(), 1, message.length(), out());
    ::fprintf(out(), "\n\n");
  }

  ::fprintf(out(), kUsageFormatStr, program.BaseName().value().c_str());

  return false;
}

bool SamplerApp::ParsePids(const std::string& pids) {
  std::vector<std::string> split;
  base::SplitString(pids, ',', &split);

  for (size_t i = 0; i < split.size(); ++i) {
    std::string s;
    ::TrimWhitespace(split[i], TRIM_ALL, &s);

    // Skip empty strings.
    if (s.empty())
      continue;

    uint32 pid = 0;
    if (!base::StringToUint(s, &pid)) {
      LOG(ERROR) << "Unable to parse \"" << s << "\" as a PID.";
      return false;
    }
    pids_.insert(pid);
  }

  if (pids_.empty()) {
    LOG(ERROR) << "--" << kPids << " must not be empty.";
    return false;
  }

  return true;
}

void SamplerApp::OnDeadModule(const SampledModuleCache::Module* module) {
  DCHECK(module != NULL);

  // Invoke our testing seam callback.
  OnStopProfiling(module);

  const SampledModuleCache::Process* process = module->process();
  DCHECK(process != NULL);

  base::FilePath basename = TraceFileWriter::GenerateTraceFileBaseName(
          process->process_info());
  base::FilePath trace_file_path = output_dir_.Append(basename);

  LOG(INFO) << "Writing module samples to \"" << trace_file_path.value()
            << "\".";

  // TODO(chrisha): If we deal with processes with multiple profiled modules
  //     or repeatedly loaded and unloaded modules, we could persist a trace
  //     file writer for each process and use it repeatedly.

  TraceFileWriter writer;
  if (!writer.Open(trace_file_path))
    return;

  if (!writer.WriteHeader(process->process_info()))
    return;

  if (!WriteTraceModuleDataRecord(module, &writer))
    return;

  if (!WriteTraceSampleDataRecord(sampling_interval_in_cycles_, module,
                                  &writer)) {
    return;
  }

  return;
}

bool SamplerApp::GetModuleSignature(
    const base::FilePath& module, ModuleSignature* sig) {
  DCHECK(sig != NULL);

  pe::PEFile pe_file;
  if (!pe_file.Init(module))
    return false;

  pe::PEFile::Signature pe_sig;
  pe_file.GetSignature(&pe_sig);

  sig->size = pe_sig.module_size;
  sig->time_date_stamp = pe_sig.module_time_date_stamp;
  sig->checksum = pe_sig.module_checksum;

  return true;
}

// Handler for Ctrl-C keypresses.
BOOL WINAPI SamplerApp::OnConsoleCtrl(DWORD ctrl_type) {
  base::AutoLock auto_lock(console_ctrl_lock_);

  // If we're getting messages we should have an owner.
  DCHECK(console_ctrl_owner_ != NULL);

  // We don't handle logoff events.
  if (ctrl_type == CTRL_LOGOFF_EVENT)
    return FALSE;

  // Any console signal means we should shutdown.
  console_ctrl_owner_->set_running(false);

  LOG(INFO) << "Caught console signal, shutting down.";

  return TRUE;
}

bool SamplerApp::running() {
  base::AutoLock auto_lock(lock_);
  return running_;
}

void SamplerApp::set_running(bool running) {
  base::AutoLock auto_lock(lock_);
  running_ = running;
}

bool SamplerApp::ModuleSignature::operator<(const ModuleSignature& rhs) const {
  if (size != rhs.size)
    return size < rhs.size;
  if (time_date_stamp != rhs.time_date_stamp)
    return time_date_stamp < rhs.time_date_stamp;
  return checksum < rhs.checksum;
}

}  // namespace sampler

// Copyright 2012 Google Inc.
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

#include "syzygy/simulate/simulator.h"

#include "syzygy/common/syzygy_version.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pe/pe_file.h"
#include "syzygy/pe/pe_utils.h"
#include "syzygy/pe/unittest_util.h"
#include "syzygy/trace/parse/parse_engine.h"

namespace simulate {

namespace {

using block_graph::BlockGraph;
using core::RelativeAddress;
using playback::Playback;
using testing::GetExeTestDataRelativePath;

class MockPlayback : public Playback {
 public:
  MockPlayback(const FilePath& module_path,
               const FilePath& instrumented_path,
               const TraceFileList& trace_files)
      : Playback(module_path,
                 instrumented_path,
                 trace_files) {
  }

  bool Init(PEFile* /*pe_file*/, ImageLayout* /*image*/, Parser* /*parser*/) {
    return true;
  }

 private:
  friend class SimulatorTest;
};

class MockParseEngine : public trace::parser::ParseEngine {
 public:
  typedef BlockGraph::AddressSpace::RangeMapConstIter RangeMapConstIter;

  MockParseEngine() : ParseEngine("MockParseEngine", true), playback_(NULL) {
  }

  bool IsRecognizedTraceFile(const FilePath &) OVERRIDE { return true; }
  bool OpenTraceFile(const FilePath &) OVERRIDE { return true; }
  bool CloseAllTraceFiles() OVERRIDE { return true; }

  bool ConsumeAllEvents() OVERRIDE;

  // The Playback used by my mock simulator.
  const Playback* playback_;
};

bool MockParseEngine::ConsumeAllEvents() {
  DCHECK(playback_ != NULL);

  const DWORD kProcessId = 0x12F8;
  const DWORD kThreadId = 0x0FA8;
  const sym_util::ModuleInformation kExeInfo = {
      0x0, 0x22222222, 0x33333333, 0x44444444, L"file_name.exe" };

  // Add dummy module information for some running process.
  if (!AddModuleInformation(kProcessId, kExeInfo))
    return false;

  // Simulate a process starting.
  base::Time time = base::Time::Now();

  sym_util::ModuleInformation dll_info = {};
  const pe::PEFile::Signature& sig = playback_->instr_signature();
  dll_info.base_address = sig.base_address.value();
  dll_info.image_checksum = sig.module_checksum;
  dll_info.image_file_name = sig.path;
  dll_info.module_size = sig.module_size;
  dll_info.time_date_stamp = sig.module_time_date_stamp;

  TraceModuleData dll_data = {};
  dll_data.module_base_addr =
      reinterpret_cast<ModuleAddr>(dll_info.base_address);
  dll_data.module_base_size = dll_info.module_size;
  dll_data.module_exe[0] = 0;
  dll_data.module_checksum = dll_info.image_checksum;
  dll_data.module_time_date_stamp = dll_info.time_date_stamp;
  wcscpy_s(dll_data.module_name,
           sizeof(dll_data.module_name),
           sig.path.c_str());

  // Simulate the process attaching to the DLL. This adds the DLL
  // to the list of modules.
  EVENT_TRACE event_record = {};
  event_record.Header.TimeStamp =
      reinterpret_cast<LARGE_INTEGER&>(time.ToFileTime());
  event_record.Header.ProcessId = kProcessId;
  event_record.Header.ThreadId = kThreadId;
  event_record.Header.Guid = kCallTraceEventClass;
  event_record.Header.Class.Type = TRACE_PROCESS_ATTACH_EVENT;
  event_record.MofData = &dll_data;
  event_record.MofLength = sizeof(dll_data);

  if (!DispatchEvent(&event_record))
    return false;

  // Simulate all of the blocks using batch events.
  static const size_t kBlockCount = playback_->image()->blocks.size();

  const size_t raw_data_size = sizeof(TraceBatchEnterData) + kBlockCount *
      sizeof(FuncCall);
  scoped_array<uint8> raw_data(new uint8[raw_data_size]);

  TraceBatchEnterData& event_data =
      *reinterpret_cast<TraceBatchEnterData*>(raw_data.get());
  event_data.thread_id = kThreadId;
  event_data.num_calls = kBlockCount;

  // Iterate through all the function entry events and add
  // them to a single batch one.
  RangeMapConstIter iter = playback_->image()->blocks.begin();
  for (int i = 0; iter != playback_->image()->blocks.end(); i++, iter++) {
    // Get the address of this block as an RVA in the instrumented module.
    RelativeAddress rva = iter->second->addr();
    rva = pdb::TranslateAddressViaOmap(playback_->omap_from(), rva);

    // Convert this to an absolute address using the base address from above.
    uint64 abs = sig.base_address.value() + rva.value();
    void* block_pointer = reinterpret_cast<void*>(abs);

    event_data.calls[i].function = block_pointer;
  }

  event_record.Header.Class.Type = TRACE_BATCH_ENTER;
  event_record.MofData = raw_data.get();
  event_record.MofLength = raw_data_size;
  if (!DispatchEvent(&event_record))
    return false;

  return true;
}

class MockSimulator : public Simulator {
 public:
  MockSimulator(const FilePath& module_path,
                const FilePath& instrumented_path,
                const TraceFileList& trace_files)
      : Simulator(module_path, instrumented_path, trace_files),
        mock_parse_engine_(NULL),
        mock_playback_(NULL) {
  }

 protected:
  MockParseEngine* mock_parse_engine_;
  MockPlayback* mock_playback_;

 private:
  friend class SimulatorTest;
};

class SimulatorTest : public testing::PELibUnitTest {
 public:
  typedef std::vector<FilePath> TraceFileList;

  void InitSimulator() {
    module_path_ = GetExeTestDataRelativePath(kDllName);
    instrumented_path_ = GetExeTestDataRelativePath(kRpcInstrumentedDllName);

    simulator_.reset(
        new MockSimulator(module_path_, instrumented_path_, trace_files_));
  }

  void InitMockTraceFileList() {
    // Assign a mock trace file.
    trace_files_ = TraceFileList(1, GetExeTestDataRelativePath(L"foo"));
  };

  void InitSingleFileTraceFileList() {
    trace_files_ = TraceFileList(1, GetExeTestDataRelativePath(
        L"rpc_traces/trace-1.bin"));
  }

  void InitMultipleFileTraceFileList() {
    const FilePath trace_files_initializer[] = {
        GetExeTestDataRelativePath(L"rpc_traces/trace-1.bin"),
        GetExeTestDataRelativePath(L"rpc_traces/trace-2.bin"),
        GetExeTestDataRelativePath(L"rpc_traces/trace-3.bin"),
        GetExeTestDataRelativePath(L"rpc_traces/trace-4.bin")
    };

    trace_files_ = Playback::TraceFileList(trace_files_initializer,
        trace_files_initializer + arraysize(trace_files_initializer));
  }

  void InsertMockParser() {
    simulator_->mock_playback_ =
        new MockPlayback(module_path_, instrumented_path_, trace_files_);
    simulator_->playback_.reset(simulator_->mock_playback_);

    simulator_->parser_.reset(new Simulator::Parser());
    simulator_->mock_parse_engine_ = new MockParseEngine();
    simulator_->mock_parse_engine_->playback_ = simulator_->mock_playback_;
    simulator_->parser_->AddParseEngine(simulator_->mock_parse_engine_);
    EXPECT_TRUE(simulator_->parser_->Init(simulator_.get()));

    simulator_->mock_playback_->pe_file_ = &simulator_->pe_file_;
    simulator_->mock_playback_->image_ = &simulator_->image_layout_;
    simulator_->mock_playback_->parser_ = simulator_->parser_.get();

    EXPECT_TRUE(simulator_->mock_playback_->InitializeParser());
  }

  // Returns a set with the expected page faults using the mock image.
  std::set<uint32> ExpectedPageFaults() {
    std::set<uint32> page_faults;
    for (int i = 0; i < 5; i++)
      page_faults.insert(i);
    page_faults.insert(6);

    return page_faults;
  }

  BlockGraph::Block* AddBlock(BlockGraph::BlockType type,
                              size_t size,
                              const char* name,
                              const BlockGraph::Section* section) {
    DCHECK(name != NULL);
    BlockGraph::Block* block =
        simulator_->block_graph_.AddBlock(type, size, name);
    block->ResizeData(size);
    if (section != NULL)
      block->set_section(section->id());
    return block;
  }

  // This generates a dummy image with all of the PE features we wish to test,
  // but it will not result in a loadable/runnable module if written.
  void GenerateDummyImage() {
    // Create the standard assortment of sections.
    BlockGraph::Section* text = simulator_->block_graph_.AddSection(
        pe::kCodeSectionName, pe::kCodeCharacteristics);

    // Create four dummy code blocks.
    BlockGraph::Block* blocks[] = {
        AddBlock(BlockGraph::CODE_BLOCK, 0x16000, "block 1", text),
        AddBlock(BlockGraph::CODE_BLOCK, 0x21000, "block 2", text),
        AddBlock(BlockGraph::CODE_BLOCK, 0x7000, "block 3", text),
        AddBlock(BlockGraph::CODE_BLOCK, 0x8000, "block 4", text)
    };

    // Initialize image_layout with the blocks I just created
    simulator_->image_layout_ = pe::ImageLayout(&simulator_->block_graph_);

    // Give addresses to those blocks.
    simulator_->image_layout_.blocks.InsertBlock(
        BlockGraph::RelativeAddress(0x0), blocks[0]);
    simulator_->image_layout_.blocks.InsertBlock(
        BlockGraph::RelativeAddress(0xB000), blocks[1]);
    simulator_->image_layout_.blocks.InsertBlock(
        BlockGraph::RelativeAddress(0x1D000), blocks[2]);
    simulator_->image_layout_.blocks.InsertBlock(
        BlockGraph::RelativeAddress(0x30000), blocks[3]);
  }

 protected:
  FilePath module_path_;
  FilePath instrumented_path_;
  TraceFileList trace_files_;
  scoped_ptr<MockSimulator> simulator_;
};

}  // namespace

TEST_F(SimulatorTest, CorrectPageFaults) {
  ASSERT_NO_FATAL_FAILURE(InitMockTraceFileList());

  module_path_ = FilePath(L"foobarbaz");
  instrumented_path_ = FilePath(L"instrumented_foobarbaz");
  simulator_.reset(
      new MockSimulator(module_path_, instrumented_path_, trace_files_));

  ASSERT_NO_FATAL_FAILURE(InsertMockParser());
  ASSERT_NO_FATAL_FAILURE(GenerateDummyImage());

  EXPECT_TRUE(simulator_->ParseTraceFiles());
  EXPECT_EQ(simulator_->page_faults(), ExpectedPageFaults());
}

TEST_F(SimulatorTest, DetectSingleFilePageFaults) {
  ASSERT_NO_FATAL_FAILURE(InitSingleFileTraceFileList());
  ASSERT_NO_FATAL_FAILURE(InitSimulator());

  EXPECT_TRUE(simulator_->ParseTraceFiles());

  // We don't know how many pagefaults the trace files will have, but
  // we know there will be some.
  EXPECT_NE(simulator_->page_faults().size(), 0u);
}

TEST_F(SimulatorTest, DetectMultipleFilePageFaults) {
  ASSERT_NO_FATAL_FAILURE(InitMultipleFileTraceFileList());
  ASSERT_NO_FATAL_FAILURE(InitSimulator());

  EXPECT_TRUE(simulator_->ParseTraceFiles());
  EXPECT_NE(simulator_->page_faults().size(), 0u);
}

}  // namespace simulate

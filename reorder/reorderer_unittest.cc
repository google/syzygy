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

#include "syzygy/reorder/reorderer.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pdb/omap.h"
#include "syzygy/pe/unittest_util.h"
#include "syzygy/trace/parse/parse_engine.h"
#include "syzygy/trace/parse/parser.h"

namespace reorder {

using call_trace::parser::ParseEngine;
using call_trace::parser::Parser;
using testing::_;
using testing::DoAll;
using testing::InSequence;
using testing::InvokeWithoutArgs;
using testing::Return;

namespace {

// A wrapper for Reorderer giving us access to some of its internals.
class TestReorderer : public Reorderer {
 public:
  TestReorderer(const FilePath& module_path,
                const FilePath& instrumented_path,
                const TraceFileList& trace_files,
                Flags flags);

  const PEFile::Signature& instr_signature() const {
    return playback_.instr_signature();
  }

  Parser& parser() { return parser_; }
  Playback* playback() { return &playback_; }
};

// A dummy order generator that does nothing but record events fed to it via
// the reorderer.
class TestOrderGenerator : public Reorderer::OrderGenerator {
 public:
  TestOrderGenerator() : Reorderer::OrderGenerator("TestOrderGenerator") {
  }

  virtual ~TestOrderGenerator() {
  }

  virtual bool OnCodeBlockEntry(const BlockGraph::Block* block,
                                RelativeAddress address,
                                uint32 process_id,
                                uint32 thread_id,
                                const Reorderer::UniqueTime& time) OVERRIDE {
    // Record the visited block.
    blocks.push_back(block);
    return true;
  }

  virtual bool CalculateReordering(const PEFile& pe_file,
                                   const ImageLayout& image,
                                   bool reorder_code,
                                   bool reorder_data,
                                   Reorderer::Order* order) OVERRIDE{
    // We don't actually generate an ordering.
    return true;
  }

  std::vector<const BlockGraph::Block*> blocks;
};

class MockOrderGenerator : public Reorderer::OrderGenerator {
 public:
  MockOrderGenerator() : Reorderer::OrderGenerator("MockOrderGenerator") {
  }

  MOCK_METHOD2(OnProcessStarted,
               bool(uint32 process_id, const Reorderer::UniqueTime& time));

  MOCK_METHOD2(OnProcessEnded,
               bool(uint32 process_id, const Reorderer::UniqueTime& time));

  MOCK_METHOD5(OnCodeBlockEntry,
               bool(const BlockGraph::Block* block,
                    RelativeAddress address,
                    uint32 process_id,
                    uint32 thread_id,
                    const Reorderer::UniqueTime& time));

  MOCK_METHOD5(CalculateReordering,
               bool(const PEFile& pe_file,
                    const ImageLayout& image,
                    bool reorder_code,
                    bool reorder_data,
                    Reorderer::Order* order));
};

// A dummy parse engine. This lets us feed hand-crafted events to any consumer.
class TestParseEngine : public ParseEngine {
 public:
  typedef Reorderer::BlockGraph BlockGraph;
  typedef Reorderer::ImageLayout ImageLayout;
  typedef Reorderer::PEFile PEFile;
  typedef Reorderer::RelativeAddress RelativeAddress;

  explicit TestParseEngine(TestReorderer* reorderer)
      : ParseEngine("TestParseEngine", true),
        reorderer_(reorderer) {
  }

  virtual ~TestParseEngine() {
  }

  virtual bool IsRecognizedTraceFile(const FilePath& trace_file_path) {
    return true;
  }

  virtual bool OpenTraceFile(const FilePath& trace_file_path) {
    return true;
  }

  virtual bool ConsumeAllEvents();

  virtual bool CloseAllTraceFiles() {
    return true;
  }

  using ParseEngine::AddModuleInformation;

  // This will hold the list of blocks that we expect the order generator to
  // build.
  std::vector<const BlockGraph::Block*> blocks;

 private:
  // The parser needs to have a pointer to the reorderer in order to get image
  // data from it for producing false events.
  TestReorderer* reorderer_;
};

TestReorderer::TestReorderer(const FilePath& module_path,
                             const FilePath& instrumented_path,
                             const TraceFileList& trace_files,
                             Flags flags)
    : Reorderer(module_path, instrumented_path, trace_files, flags) {
}

const DWORD kProcessId = 0xAAAAAAAA;
const DWORD kThreadId = 0xBBBBBBBB;
const sym_util::ModuleInformation kExeInfo = {
    0x11111111, 0x22222222, 0x33333333, 0x44444444, L"file_name.exe" };

bool TestParseEngine::ConsumeAllEvents() {
  // Add dummy module information for some running process.
  if (!AddModuleInformation(kProcessId, kExeInfo))
    return false;

  // Simulate a process starting.
  base::Time time = base::Time::Now();
  event_handler_->OnProcessStarted(time, kProcessId);

  sym_util::ModuleInformation dll_info = {};
  const PEFile::Signature& sig = reorderer_->instr_signature();
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

  // Simulate the process and thread attaching to the DLL. This adds the DLL
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

  event_record.Header.Class.Type = TRACE_THREAD_ATTACH_EVENT;
  if (!DispatchEvent(&event_record))
    return false;

  // Get all of the code blocks in the original image.
  BlockGraph::AddressSpace::RangeMapConstIter block_it =
      reorderer_->playback()->image()->blocks.begin();
  for (; block_it != reorderer_->playback()->image()->blocks.end();
       ++block_it) {
    if (block_it->second->type() == BlockGraph::CODE_BLOCK)
      blocks.push_back(block_it->second);
  }

  // Shuffle the code blocks.
  std::random_shuffle(blocks.begin(), blocks.end());

  // Simulate half of the blocks using batch events.
  static const size_t kBatchCallCount = 5;
  size_t i = 0;
  for (; i < blocks.size() / 2; i += kBatchCallCount) {
    uint8 raw_data[sizeof(TraceBatchEnterData) +
                   kBatchCallCount * sizeof(FuncCall)] = {};
    TraceBatchEnterData& event_data =
       *reinterpret_cast<TraceBatchEnterData*>(&raw_data);
    event_data.thread_id = kThreadId;
    event_data.num_calls = kBatchCallCount;

    for (size_t j = 0; j < kBatchCallCount; ++j) {
      // Get the address of this block as an RVA in the instrumented module.
      RelativeAddress rva = blocks[i + j]->addr();
      rva = pdb::TranslateAddressViaOmap(reorderer_->playback()->omap_from(),
                                         rva);

      // Convert this to an absolute address using the base address from above.
      uint64 abs = sig.base_address.value() + rva.value();
      void* block_pointer = reinterpret_cast<void*>(abs);

      event_data.calls[j].function = block_pointer;
    }

    event_record.Header.Class.Type = TRACE_BATCH_ENTER;
    event_record.MofData = &raw_data;
    event_record.MofLength = sizeof(raw_data);
    if (!DispatchEvent(&event_record))
      return false;
  }

  // Simulate entry/exit pairs with the remaining blocks.
  for (; i < blocks.size(); ++i) {
    // Get the address of this block as an RVA in the instrumented module.
    RelativeAddress rva = blocks[i]->addr();
    rva = pdb::TranslateAddressViaOmap(reorderer_->playback()->omap_from(),
                                       rva);

    // Convert this to an absolute address using the base address from above.
    uint64 abs = sig.base_address.value() + rva.value();
    void* block_pointer = reinterpret_cast<void*>(abs);

    TraceEnterEventData event_data = {};
    event_data.function = block_pointer;

    // Simulate an entry event.
    event_record.Header.Class.Type = TRACE_ENTER_EVENT;
    event_record.MofData = &event_data;
    event_record.MofLength = sizeof(event_data);
    if (!DispatchEvent(&event_record))
      return false;

    // Simulate a corresponding exit event.
    event_record.Header.Class.Type = TRACE_EXIT_EVENT;
    if (!DispatchEvent(&event_record))
      return false;
  }

  // Simulate the thread and process detaching from the DLL.
  event_record.Header.Class.Type = TRACE_THREAD_DETACH_EVENT;
  event_record.MofData = &dll_data;
  event_record.MofLength = sizeof(dll_data);
  if (!DispatchEvent(&event_record))
    return false;

  event_record.Header.Class.Type = TRACE_PROCESS_DETACH_EVENT;
  if (!DispatchEvent(&event_record))
    return false;

  // Simulate the process ending.
  event_handler_->OnProcessEnded(time, kProcessId);

  return true;
}

class ReordererTest : public testing::PELibUnitTest {
 public:
  typedef testing::PELibUnitTest Super;

  typedef Reorderer::BlockGraph BlockGraph;
  typedef Reorderer::ImageLayout ImageLayout;
  typedef Reorderer::PEFile PEFile;
  typedef Reorderer::RelativeAddress RelativeAddress;

  ReordererTest() : test_parse_engine_(NULL) {
  }

  void SetUp() OVERRIDE {
    Super::SetUp();

    // Create the dummy trace file list.
    Reorderer::TraceFileList trace_file_list;
    trace_file_list.push_back(FilePath(L"foo"));

    // Set up the reorderer. These tests rely on etw_instrumented_test_dll.dll,
    // as generated by the test_data project.
    const Reorderer::Flags kFlags = Reorderer::kFlagReorderCode |
                                    Reorderer::kFlagReorderData;
    test_reorderer_.reset(
        new TestReorderer(
            testing::GetExeTestDataRelativePath(kDllName),
            testing::GetExeTestDataRelativePath(kEtwInstrumentedDllName),
            trace_file_list,
            kFlags));

    // Setup the test parse engine and register it with the parser used
    // by the test reorderer. Note that ownership of the pointer is also
    // being passed.
    ASSERT_TRUE(test_parse_engine_ == NULL);
    test_parse_engine_ = new TestParseEngine(test_reorderer_.get());
    ASSERT_TRUE(test_parse_engine_ != NULL);
    test_reorderer_->parser().AddParseEngine(test_parse_engine_);
  }

  // A reorderer will be initialized, in SetUp(), for each test run.
  scoped_ptr<TestReorderer> test_reorderer_;

  // The reorderer needs to be set up to use a custom parse engine before a
  // call to Reorder. This must be heap allocated and the responsibility for
  // deleting it rests with the parser.
  TestParseEngine* test_parse_engine_;
};

}  // namespace

TEST_F(ReordererTest, ValidateCallbacks) {
  MockOrderGenerator mock_order_generator;

  // Setup the expected calls.
  InSequence s;
  EXPECT_CALL(mock_order_generator, OnProcessStarted(_, _))
      .WillOnce(Return(true));
  EXPECT_CALL(mock_order_generator, OnCodeBlockEntry(_, _, _, _, _))
      .WillRepeatedly(Return(true));
  EXPECT_CALL(mock_order_generator, OnProcessEnded(_, _))
      .WillOnce(Return(true));
  EXPECT_CALL(mock_order_generator, CalculateReordering(_, _, _, _, _))
      .WillOnce(Return(true));

  // Run the reorderer.
  Reorderer::Order order;
  PEFile pe_file;
  BlockGraph block_graph;
  ImageLayout image_layout(&block_graph);
  EXPECT_TRUE(test_reorderer_->Reorder(&mock_order_generator,
                                      &order,
                                      &pe_file,
                                      &image_layout));
}

TEST_F(ReordererTest, Reorder) {
  TestOrderGenerator test_order_generator;

  // Run the reorderer.
  Reorderer::Order order;
  PEFile pe_file;
  BlockGraph block_graph;
  ImageLayout image_layout(&block_graph);
  EXPECT_TRUE(test_reorderer_->Reorder(&test_order_generator,
                                      &order,
                                      &pe_file,
                                      &image_layout));

  // We expect the order generator to have come up with the same list of
  // blocks that the parse engine used for generating dummy trace events.
  EXPECT_EQ(test_parse_engine_->blocks,
            test_order_generator.blocks);
}

}  // namespace reorder

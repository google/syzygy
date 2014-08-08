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

#include "syzygy/reorder/reorderer.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pdb/omap.h"
#include "syzygy/pe/unittest_util.h"
#include "syzygy/reorder/order_generator_test.h"
#include "syzygy/trace/parse/parse_engine.h"
#include "syzygy/trace/parse/parser.h"

namespace reorder {

namespace {

using block_graph::BlockGraph;
using block_graph::ConstBlockVector;
using testing::_;
using testing::BlockSpecsAreEqual;
using testing::DoAll;
using testing::InSequence;
using testing::InvokeWithoutArgs;
using testing::OrdersAreEqual;
using testing::Return;
using testing::SectionSpecsAreEqual;
using trace::parser::ParseEngine;
using trace::parser::Parser;

typedef Reorderer::Order::BlockSpec BlockSpec;
typedef Reorderer::Order::SectionSpec SectionSpec;
typedef Reorderer::Order::SectionSpecVector SectionSpecVector;

// A wrapper for Reorderer giving us access to some of its internals.
class TestReorderer : public Reorderer {
 public:
  TestReorderer(const base::FilePath& module_path,
                const base::FilePath& instrumented_path,
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
                                   Reorderer::Order* order) OVERRIDE {
    // We don't actually generate an ordering.
    return true;
  }

  ConstBlockVector blocks;
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
  typedef block_graph::BlockGraph BlockGraph;
  typedef core::RelativeAddress RelativeAddress;
  typedef Reorderer::ImageLayout ImageLayout;
  typedef Reorderer::PEFile PEFile;

  explicit TestParseEngine(TestReorderer* reorderer)
      : ParseEngine("TestParseEngine", true),
        reorderer_(reorderer) {
  }

  virtual ~TestParseEngine() {
  }

  virtual bool IsRecognizedTraceFile(const base::FilePath& trace_file_path) {
    return true;
  }

  virtual bool OpenTraceFile(const base::FilePath& trace_file_path) {
    return true;
  }

  virtual bool ConsumeAllEvents();

  virtual bool CloseAllTraceFiles() {
    return true;
  }

  using ParseEngine::AddModuleInformation;

  // This will hold the list of blocks that we expect the order generator to
  // build.
  ConstBlockVector blocks;

 private:
  // The parser needs to have a pointer to the reorderer in order to get image
  // data from it for producing false events.
  TestReorderer* reorderer_;
};

TestReorderer::TestReorderer(const base::FilePath& module_path,
                             const base::FilePath& instrumented_path,
                             const TraceFileList& trace_files,
                             Flags flags)
    : Reorderer(module_path, instrumented_path, trace_files, flags) {
}

const DWORD kProcessId = 0xAAAAAAAA;
const DWORD kThreadId = 0xBBBBBBBB;
const pe::ModuleInformation kExeInfo(
    L"file_name.exe", pe::PEFile::AbsoluteAddress(0x11111111), 0x22222222,
    0x33333333, 0x44444444);

bool TestParseEngine::ConsumeAllEvents() {
  // Add dummy module information for some running process.
  if (!AddModuleInformation(kProcessId, kExeInfo))
    return false;

  // Simulate a process starting.
  base::Time time = base::Time::Now();
  event_handler_->OnProcessStarted(time, kProcessId, NULL);

  const pe::ModuleInformation& dll_info = reorderer_->instr_signature();

  TraceModuleData dll_data = {};
  dll_data.module_base_addr =
      reinterpret_cast<ModuleAddr>(dll_info.base_address.value());
  dll_data.module_base_size = dll_info.module_size;
  dll_data.module_exe[0] = 0;
  dll_data.module_checksum = dll_info.module_checksum;
  dll_data.module_time_date_stamp = dll_info.module_time_date_stamp;
  wcscpy_s(dll_data.module_name,
           arraysize(dll_data.module_name),
           dll_info.path.c_str());

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

  // Get all of the non-padding code blocks in the original image. (Padding
  // blocks don't make it to the instrumented DLL, so any events with addresses
  // that refer to padding blocks will fail to resolve via the OMAP info.)
  BlockGraph::AddressSpace::RangeMapConstIter block_it =
      reorderer_->playback()->image()->blocks.begin();
  for (; block_it != reorderer_->playback()->image()->blocks.end();
       ++block_it) {
    if (block_it->second->type() == BlockGraph::CODE_BLOCK &&
        (block_it->second->attributes() & BlockGraph::PADDING_BLOCK) == 0) {
      blocks.push_back(block_it->second);
    }
  }

  // Shuffle the code blocks.
  std::random_shuffle(blocks.begin(), blocks.end());

  // Simulate half of the blocks using batch events.
  static const size_t kBatchCallCount = 5;
  size_t i = 0;
  for (; i < blocks.size() / 2; i += kBatchCallCount) {
    uint8 raw_data[sizeof(TraceBatchEnterData) +
                   kBatchCallCount * sizeof(TraceEnterEventData)] = {};
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
      uint64 abs = dll_info.base_address.value() + rva.value();
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
    uint64 abs = dll_info.base_address.value() + rva.value();
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

  typedef block_graph::BlockGraph BlockGraph;
  typedef core::RelativeAddress RelativeAddress;
  typedef Reorderer::ImageLayout ImageLayout;
  typedef Reorderer::PEFile PEFile;

  ReordererTest() : test_parse_engine_(NULL) {
  }

  void SetUp() OVERRIDE {
    Super::SetUp();

    // Create the dummy trace file list.
    Reorderer::TraceFileList trace_file_list;
    trace_file_list.push_back(base::FilePath(L"foo"));

    // Set up the reorderer. These tests rely on
    // call_trace_instrumented_test_dll.dll, as generated by the test_data
    // project.
    const Reorderer::Flags kFlags = Reorderer::kFlagReorderCode |
                                    Reorderer::kFlagReorderData;
    test_reorderer_.reset(new TestReorderer(
        testing::GetExeTestDataRelativePath(testing::kTestDllName),
        testing::GetExeTestDataRelativePath(
            testing::kCallTraceInstrumentedTestDllName),
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

TEST(OrderTest, OrderConstructor) {
  Reorderer::Order order;
  EXPECT_TRUE(order.sections.empty());
  EXPECT_TRUE(order.comment.empty());
}

TEST(OrderTest, SectionSpecConstructorsAndCopies) {
  // Create default constructed section spec.
  Reorderer::Order::SectionSpec default_section_spec;
  EXPECT_EQ(Reorderer::Order::SectionSpec::kNewSectionId,
            default_section_spec.id);
  EXPECT_TRUE(default_section_spec.name.empty());
  EXPECT_EQ(0U, default_section_spec.characteristics);
  EXPECT_TRUE(default_section_spec.blocks.empty());

  // Create a customized section spec.
  Reorderer::Order::SectionSpec other_section_spec;
  EXPECT_TRUE(SectionSpecsAreEqual(default_section_spec, other_section_spec));
  other_section_spec.id = 7;
  other_section_spec.characteristics = 19;
  other_section_spec.name = "other";
  EXPECT_FALSE(SectionSpecsAreEqual(default_section_spec, other_section_spec));

  // Copy construct a section spec.
  Reorderer::Order::SectionSpec copied_section_spec(other_section_spec);
  EXPECT_TRUE(SectionSpecsAreEqual(other_section_spec, copied_section_spec));
  EXPECT_FALSE(SectionSpecsAreEqual(copied_section_spec, default_section_spec));

  // Assign to the default section spec.
  default_section_spec = other_section_spec;
  EXPECT_TRUE(SectionSpecsAreEqual(copied_section_spec, default_section_spec));
}

TEST(OrderTest, BlockSpecConstructorsAndCopier) {
  static const BlockGraph::Block* kFauxBlockPtr =
      reinterpret_cast<BlockGraph::Block*>(0xCCCCCCCC);

  // Default construct a block spec.
  Reorderer::Order::BlockSpec default_block_spec;
  EXPECT_EQ(NULL, default_block_spec.block);
  EXPECT_TRUE(default_block_spec.basic_block_offsets.empty());

  // Explicitly construct a block spec.
  Reorderer::Order::BlockSpec explicit_block_spec(kFauxBlockPtr);
  EXPECT_EQ(kFauxBlockPtr, explicit_block_spec.block);
  EXPECT_TRUE(explicit_block_spec.basic_block_offsets.empty());

  // Default construct another block spec.
  Reorderer::Order::BlockSpec block_spec;
  EXPECT_TRUE(BlockSpecsAreEqual(default_block_spec, block_spec));

  // Modify the block spec.
  block_spec.block = kFauxBlockPtr;
  block_spec.basic_block_offsets.push_back(0);
  block_spec.basic_block_offsets.push_back(8);
  EXPECT_FALSE(BlockSpecsAreEqual(default_block_spec, block_spec));
  EXPECT_FALSE(BlockSpecsAreEqual(explicit_block_spec, block_spec));

  // Copy construct a block spec.
  Reorderer::Order::BlockSpec copied_block_spec(block_spec);
  EXPECT_TRUE(BlockSpecsAreEqual(block_spec, copied_block_spec));
  EXPECT_FALSE(BlockSpecsAreEqual(default_block_spec, block_spec));
  EXPECT_FALSE(BlockSpecsAreEqual(explicit_block_spec, block_spec));

  // Assign to the explicit block spec.
  explicit_block_spec = block_spec;
  EXPECT_TRUE(BlockSpecsAreEqual(copied_block_spec, explicit_block_spec));
}

TEST(OrderTest, SerializeToJsonRoundTrip) {
  // Build a dummy block graph.
  BlockGraph block_graph;
  BlockGraph::Section* section1 = block_graph.AddSection(".text", 0);
  BlockGraph::Section* section2 = block_graph.AddSection(".rdata", 0);
  BlockGraph::Block* block1 = block_graph.AddBlock(BlockGraph::CODE_BLOCK, 10,
                                                   "block1");
  BlockGraph::Block* block2 = block_graph.AddBlock(BlockGraph::DATA_BLOCK, 10,
                                                   "block2");
  BlockGraph::Block* block3 = block_graph.AddBlock(BlockGraph::DATA_BLOCK, 10,
                                                   "block3");
  block1->set_section(section1->id());
  block2->set_section(section2->id());
  block3->set_section(section2->id());

  // Build a dummy image layout.
  pe::ImageLayout layout(&block_graph);
  pe::ImageLayout::SectionInfo section_info1 = {};
  section_info1.name = section1->name();
  section_info1.addr = core::RelativeAddress(0x1000);
  section_info1.size = 0x1000;
  section_info1.data_size = 0x1000;
  layout.sections.push_back(section_info1);

  pe::ImageLayout::SectionInfo section_info2 = {};
  section_info2.name = section2->name();
  section_info2.addr = core::RelativeAddress(0x2000);
  section_info2.size = 0x1000;
  section_info2.data_size = 0x1000;
  layout.sections.push_back(section_info2);

  layout.blocks.InsertBlock(section_info1.addr,
                            block1);
  layout.blocks.InsertBlock(section_info2.addr,
                            block2);
  layout.blocks.InsertBlock(section_info2.addr + block2->size(),
                            block3);

  // Build a dummy order.
  Reorderer::Order order;
  order.comment = "This is a comment.";
  order.sections.resize(2);
  order.sections[0].id = section1->id();
  order.sections[0].name = section1->name();
  order.sections[0].characteristics = section1->characteristics();
  order.sections[0].blocks.push_back(BlockSpec(block1));
  order.sections[0].blocks.back().basic_block_offsets.push_back(0);
  order.sections[0].blocks.back().basic_block_offsets.push_back(8);
  order.sections[1].id = section2->id();
  order.sections[1].name = section2->name();
  order.sections[1].characteristics = section2->characteristics();
  order.sections[1].blocks.push_back(BlockSpec(block2));
  order.sections[1].blocks.push_back(BlockSpec(block3));

  base::FilePath module = testing::GetExeTestDataRelativePath(
      testing::kTestDllName);
  pe::PEFile pe_file;
  ASSERT_TRUE(pe_file.Init(module));

  // Serialize the order.
  base::FilePath temp_file;
  ASSERT_TRUE(base::CreateTemporaryFile(&temp_file));
  EXPECT_TRUE(order.SerializeToJSON(pe_file, temp_file, true));

  // Get the original module from the file.
  base::FilePath orig_module;
  EXPECT_TRUE(Reorderer::Order::GetOriginalModulePath(temp_file, &orig_module));
  EXPECT_EQ(module, orig_module);

  // Deserialize it.
  Reorderer::Order order2;
  EXPECT_FALSE(OrdersAreEqual(order, order2));
  EXPECT_TRUE(order2.LoadFromJSON(pe_file, layout, temp_file));

  // Expect them to be the same.
  EXPECT_TRUE(OrdersAreEqual(order, order2));

  EXPECT_TRUE(base::DeleteFile(temp_file, false));
}

}  // namespace reorder

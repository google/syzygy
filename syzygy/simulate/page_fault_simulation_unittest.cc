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

#include "syzygy/simulate/page_fault_simulation.h"

#include "base/values.h"
#include "base/files/scoped_temp_dir.h"
#include "base/json/json_reader.h"
#include "syzygy/common/syzygy_version.h"
#include "syzygy/core/random_number_generator.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pdb/omap.h"
#include "syzygy/pe/unittest_util.h"

namespace simulate {

namespace {

using base::DictionaryValue;
using base::Value;
using block_graph::BlockGraph;

class PageFaultSimulatorTest : public testing::PELibUnitTest {
 public:
  typedef PageFaultSimulation::PageSet PageSet;

  struct MockBlockInfo {
    uint32 start;
    size_t size;
    BlockGraph::Block* block;

    MockBlockInfo(uint32 start_, size_t size_, BlockGraph* block_graph)
        : start(start_), size(size_), block(NULL) {
      DCHECK(block_graph != NULL);
      block = block_graph->AddBlock(BlockGraph::CODE_BLOCK, size_, "block");
      block->set_addr(core::RelativeAddress(start));
      block->set_size(size);
    }

    MockBlockInfo()
        : start(0U), size(0U), block(NULL) {
    }
  };
  typedef std::vector<MockBlockInfo> MockBlockInfoList;

  PageFaultSimulatorTest() : random_(123) {
  }

  void SetUp() {
    ASSERT_NO_FATAL_FAILURE(CreateTemporaryDir(&temp_dir_));

    simulation_.reset(new PageFaultSimulation());
    ASSERT_TRUE(simulation_ != NULL);

    blocks_[0] = MockBlockInfo(0x0, 0x50, &block_graph_);
    blocks_[1] = MockBlockInfo(0x0, 0x100, &block_graph_);
    blocks_[2] = MockBlockInfo(0x350, 0x100, &block_graph_);
    blocks_[3] = MockBlockInfo(0x1000, 0x50, &block_graph_);
  }

  // Checks if the given address is on one of our mock blocks.
  // @param addr The address to check.
  // @returns true if a block that contains the given address exists,
  //     false on otherwise.
  bool AddressInBlocks(size_t addr) {
    for (size_t i = 0; i < arraysize(blocks_); i++) {
      if (blocks_[i].start <= addr &&
          blocks_[i].start + blocks_[i].size > addr)
        return true;
    }

    return false;
  }

  // Check whether all the pages loaded in simulator correspond to one of our
  // blocks, given the current page_size and pages_per_code_fault parameters.
  // @returns true if all the pages are contained in our mock blocks,
  //     false on otherwise.
  bool CorrectPageFaults() {
    PageSet::const_iterator iter = simulation_->pages().begin();
    for (; iter != simulation_->pages().end(); ++iter) {
      bool block_found = false;

      // If this address was loaded, then some address between this one and
      // the one pages_per_code_fault pages before should have triggered
      // a page fault.
      for (uint32 j = 0;
           j <= *iter && j < simulation_->pages_per_code_fault();
           j++) {
        if (AddressInBlocks((*iter - j) * simulation_->page_size())) {
          block_found = true;
          break;
        }
      }

      if (!block_found)
        return false;
    }

    return true;
  }

  // Gives a random number in the range [from, to), or 0 if the range is empty.
  // @param from The lowest possible return value.
  // @param to The number after the highest possible return value.
  uint32 Random(uint32 from, uint32 to) {
    int size = to - from;
    if (from > to) {
      // This should never be reached.
      ADD_FAILURE();
      return 0;
    }

    if (size == 0)
      return 0;

    return random_(size) + from;
  }

  // Add 5 random blocks that won't generate any page fault.
  // @param mock_block_list The MockBlockInfoList where the blocks will
  //     be appended. This list should already generate page faults covering
  //     the range [start, start + size).
  // @param start The start of the output sequence.
  // @param size The size of the output sequence.
  void AddRandomBlocks(
      MockBlockInfoList &mock_block_list, uint32 start, size_t size) {
    for (uint32 i = 0; i < 5; i++) {
      uint32 block_start = Random(start, start + size);
      size_t block_size = Random(1, start + size - block_start);
      mock_block_list.push_back(
          MockBlockInfo(block_start, block_size, &block_graph_));
    }
  }

  // Generate a random MockBlockInfoList that should make PageFaultSimulation
  // output the sequence [start, start + size).
  // @param start The start of the output sequence.
  // @param size The size of the output sequence.
  // @param avg_length The average length of each page fault generated by the
  //     resulting input data.
  MockBlockInfoList GeneratePartRandomInput(uint32 start,
                                            size_t size,
                                            size_t avg_length) {
    MockBlockInfoList input;

    if (size == 0)
      return input;

    uint32 page_fault_size = simulation_->pages_per_code_fault() *
        simulation_->page_size();

    if (size < page_fault_size) {
      // If the size of this part is smaller than the number of bytes loaded
      // into memory in each page fault, then the given output was impossible,
      // so this should never be reached.
      ADD_FAILURE();
      return input;
    }

    int fault = start + size - page_fault_size;
    uint32 current_size = 0;

    // The block page_fault_size bytes from the end of each sequence should
    // always be loaded.
    input.push_back(
        MockBlockInfo(fault, Random(1, page_fault_size), &block_graph_));

    fault--;
    for (; fault >= static_cast<int>(start); fault--) {
      current_size++;

      // Randomly choose with 1 / avg_length probability whether to add blocks
      // that would raise a page fault in the current byte.
      if (random_(avg_length) == 0) {
        input.push_back(MockBlockInfo(fault,
            Random(page_fault_size * (current_size / page_fault_size) + 1,
                   start + size - fault),
            &block_graph_));

        current_size = 0;
      }
    }
    // Add the bytes that weren't pagefaulted in a single big block.
    if (current_size > 0)
      input.push_back(MockBlockInfo(start,
          Random(page_fault_size * (current_size / page_fault_size) + 1,
                 size),
          &block_graph_));

    // Add several random blocks at the end of the input that won't
    // have any effect on the output.
    AddRandomBlocks(input, start, size);
    return input;
  }

  // Generate a random MockBlockInfoList that outputs output.
  // This function separates output into blocks of contiguous sequences,
  // creates a block that should raise a pagefault in the position
  // size - cluster_size, and for every element before that creates a
  // block that should raise another one with 1 / avg_length probability.
  // It also adds a few bogus blocks that shouldn't change the output, and
  // shuffles the list of inputs for contiguous sequences on the output.
  // @param output The output that should come from the returned input.
  // @param avg_length The average length of each page fault generated by the
  //     resulting input data.
  MockBlockInfoList GenerateRandomInput(PageSet output, size_t avg_length) {
    // A list with different "groups" of mock blocks.
    std::vector<MockBlockInfoList> input_list;
    uint32 last = 0;
    uint32 size = 0;

    // Search through the output for groups of adjacent numbers, and add a
    // MockBlockInfoList that would generate these numbers to input_list.
    PageSet::iterator iter = output.begin();
    for (; iter != output.end(); ++iter) {
      if (last != 0 && *iter - last > 1) {
        input_list.push_back(
            GeneratePartRandomInput(last - size + 1, size, avg_length));
        size = 0;
      }

      size++;
      last = *iter;
    }
    input_list.push_back(
        GeneratePartRandomInput(last - size + 1, size, avg_length));

    // Shuffle the groups of adjacent numbers.
    std::random_shuffle(input_list.begin(), input_list.end(), random_);

    // Append all the elements of each element of input_list to a single
    // MockBlockInfoList and return it.
    MockBlockInfoList input;
    for (size_t i = 0; i < input_list.size(); i++)
      input.insert(input.end(), input_list[i].begin(), input_list[i].end());

    return input;
  }

 protected:
  scoped_ptr<PageFaultSimulation> simulation_;

  base::FilePath temp_dir_;
  MockBlockInfo blocks_[4];
  core::RandomNumberGenerator random_;
  const base::Time time_;

  BlockGraph block_graph_;
};

}  // namespace

TEST_F(PageFaultSimulatorTest, RandomInput) {
  static const int output1[] = {1, 2, 3, 4};
  static const int output2[] = {1, 2, 3, 4, 5, 6, 12, 13, 14, 15, 16, 20, 21,
      22, 23, 100, 101, 102, 103, 104, 105};
  static const int output3[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
      15, 16, 17, 18, 19, 20, 21, 22, 23};
  static const int output4[] = {1, 2, 3, 4, 100, 101, 102, 103, 200, 201, 202,
      203};

  const PageSet outputs[] = {
      PageSet(output1, output1 + arraysize(output1)),
      PageSet(output2, output2 + arraysize(output2)),
      PageSet(output3, output3 + arraysize(output3)),
      PageSet(output4, output4 + arraysize(output4))
  };

  for (uint32 i = 0; i < 1000; i++) {
    // Make simulation_ a new instance of PageFaultSimulator.
    simulation_.reset(new PageFaultSimulation());
    ASSERT_TRUE(simulation_ != NULL);

    simulation_->OnProcessStarted(time_, 1);
    simulation_->set_pages_per_code_fault(4);

    // Choose a random output, create an input with it,
    // and simulate that input.
    PageSet output = outputs[random_(arraysize(outputs))];
    MockBlockInfoList input =
        GenerateRandomInput(output, random_(output.size()) + 1);

    for (size_t i = 0; i < input.size(); i++)
      simulation_->OnFunctionEntry(time_, input[i].block);

    std::stringstream input_string;
    input_string << '{';
    for (size_t i = 0; i < input.size(); i++) {
      input_string << '(' << input[i].start << ", ";
      input_string << input[i].size << "), ";
    }
    input_string << '}';

    ASSERT_EQ(simulation_->pages(), output) <<
        "Failed with input " << input_string.str();
  }
}

TEST_F(PageFaultSimulatorTest, ExactPageFaults) {
  simulation_->OnProcessStarted(time_, 1);
  simulation_->set_page_size(1);
  simulation_->set_pages_per_code_fault(4);

  MockBlockInfo blocks[] = {
      MockBlockInfo(0, 3, &block_graph_),
      MockBlockInfo(2, 2, &block_graph_),
      MockBlockInfo(5, 5, &block_graph_)
  };

  for (uint32 i = 0; i < arraysize(blocks); i++) {
    simulation_->OnFunctionEntry(time_, blocks[i].block);
  }

  PageSet::key_type expected_pages[] = {0, 1, 2, 3, 5, 6, 7, 8, 9, 10, 11, 12};
  EXPECT_EQ(simulation_->fault_count(), 3);
  EXPECT_EQ(simulation_->pages(), PageSet(expected_pages, expected_pages +
      arraysize(expected_pages)));
}

TEST_F(PageFaultSimulatorTest, CorrectPageFaults) {
  simulation_->OnProcessStarted(time_, 1);

  for (int i = 0; i < arraysize(blocks_); i++) {
    simulation_->OnFunctionEntry(time_, blocks_[i].block);
  }

  EXPECT_EQ(simulation_->fault_count(), 74);
  EXPECT_TRUE(CorrectPageFaults());
}

TEST_F(PageFaultSimulatorTest, CorrectPageFaultsWithBigPages) {
  simulation_->OnProcessStarted(time_, 1);
  simulation_->set_page_size(0x8000);

  for (int i = 0; i < arraysize(blocks_); i++) {
    simulation_->OnFunctionEntry(time_, blocks_[i].block);
  }

  EXPECT_EQ(simulation_->fault_count(), 1);
  EXPECT_TRUE(CorrectPageFaults());
}

TEST_F(PageFaultSimulatorTest, CorrectPageFaultsWithFewPagesPerCodeFault) {
  simulation_->OnProcessStarted(time_, 1);
  simulation_->set_pages_per_code_fault(3);

  for (int i = 0; i < arraysize(blocks_); i++) {
    simulation_->OnFunctionEntry(time_, blocks_[i].block);
  }

  EXPECT_EQ(simulation_->fault_count(), 199);
  EXPECT_TRUE(CorrectPageFaults());
}

TEST_F(PageFaultSimulatorTest, JSONSucceeds) {
  simulation_->OnProcessStarted(time_, 1);

  for (int i = 0; i < arraysize(blocks_); i++) {
    simulation_->OnFunctionEntry(time_, blocks_[i].block);
  }

  // Output JSON data to a file.
  base::FilePath path;
  base::ScopedFILE temp_file;
  temp_file.reset(base::CreateAndOpenTemporaryFileInDir(
      temp_dir_, &path));

  ASSERT_TRUE(temp_file.get() != NULL);
  ASSERT_TRUE(simulation_->SerializeToJSON(temp_file.get(), false));
  temp_file.reset();

  // Read the JSON file we just wrote.
  std::string file_string;
  ASSERT_TRUE(base::ReadFileToString(path, &file_string));

  scoped_ptr<Value> value(base::JSONReader::Read(file_string));
  ASSERT_TRUE(value.get() != NULL);
  ASSERT_TRUE(value->IsType(Value::TYPE_DICTIONARY));

  const DictionaryValue* outer_dict =
      static_cast<const DictionaryValue*>(value.get());

  static const char page_size_key[] = "page_size";
  static const char pages_per_code_fault_key[] = "pages_per_code_fault";
  static const char fault_count_key[] = "fault_count";
  static const char loaded_pages_key[] = "loaded_pages";

  int page_size = 0, pages_per_code_fault = 0, fault_count = 0;
  const base::ListValue* loaded_pages = NULL;

  outer_dict->GetInteger(page_size_key, &page_size);
  outer_dict->GetInteger(pages_per_code_fault_key, &pages_per_code_fault);
  outer_dict->GetInteger(fault_count_key, &fault_count);
  outer_dict->GetList(loaded_pages_key, &loaded_pages);

  EXPECT_EQ(page_size, 1);
  EXPECT_EQ(pages_per_code_fault, 8);
  EXPECT_EQ(fault_count, 74);

  ASSERT_TRUE(loaded_pages != NULL);

  // Compare it to our own data.
  PageSet expected_pages = simulation_->pages();
  ASSERT_EQ(expected_pages.size(), loaded_pages->GetSize());

  PageSet::iterator expected_pages_iter = expected_pages.begin();
  base::ListValue::const_iterator loaded_pages_iter = loaded_pages->begin();

  for (; expected_pages_iter != expected_pages.end();
       expected_pages_iter++, loaded_pages_iter++) {
    int page = 0;
    ASSERT_EQ((*loaded_pages_iter)->GetType(), Value::TYPE_INTEGER);
    ASSERT_TRUE((*loaded_pages_iter)->GetAsInteger(&page));

    EXPECT_EQ(*expected_pages_iter, implicit_cast<uint32>(page));
  }
}

}  // namespace simulate

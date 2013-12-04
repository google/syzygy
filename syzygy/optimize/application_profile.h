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
//
// The ApplicationProfile class is used to hold metrics taken by instrumenting
// and running the application. Profile guided optimisations use this class to
// retrieve information about runtime metrics.
//
// Example:
//   ApplicationProfile profile(&image_layout);
//   profile.ImportFrequencies(frequencies);
//   profile.ComputeGlobalProfile();
//
//   foreach block in block_graph {
//     ApplicationProfile::BlockProfile* bp = profile.GetBlockProfile();
//     if (bp->percentile() < 0.05)
//       LOG(INFO) << "This function is probably hot: " << block->name();
//   }
//
// Transformations are responsible for updating metrics when possible.

#ifndef SYZYGY_OPTIMIZE_APPLICATION_PROFILE_H_
#define SYZYGY_OPTIMIZE_APPLICATION_PROFILE_H_

#include <map>

#include "syzygy/block_graph/basic_block.h"
#include "syzygy/block_graph/basic_block_subgraph.h"
#include "syzygy/grinder/basic_block_util.h"
#include "syzygy/pe/image_layout.h"

namespace optimize {

// Forward declaration.
class SubGraphProfile;

// This class holds profile information for a block_graph.
class ApplicationProfile {
 public:
  typedef block_graph::BasicBlockSubGraph BasicBlockSubGraph;
  typedef block_graph::BlockGraph BlockGraph;
  typedef grinder::basic_block_util::IndexedFrequencyMap IndexedFrequencyMap;
  typedef grinder::basic_block_util::EntryCountType EntryCountType;
  typedef pe::ImageLayout ImageLayout;

  // Forward declaration.
  class BlockProfile;
  typedef std::map<BlockGraph::BlockId, BlockProfile> ProfileMap;

  // Constructor.
  // @param image_layout The image layout.
  // @note |image_layout| must remains alive until this class get destroyed.
  explicit ApplicationProfile(const ImageLayout* image_layout);

  // Retrieve the profile for a given block.
  // @param block the block to find profile information.
  // @returns the profile of the block or singleton empty profile when there is
  //     no information available.
  const BlockProfile* GetBlockProfile(const BlockGraph::Block* block) const;

  // @returns the global temperature of the basic block;
  // @note Invalid until the call to ComputeGlobalProfile.
  double global_temperature() const { return global_temperature_; }

  // Compute global profile and update block profiles contribution.
  // @returns true on success, false otherwise.
  // @note BlockProfile.percentile() and GetGlobalTemperature() aren't valid
  //     before this function is called.
  bool ComputeGlobalProfile();

  // Compute profile information for basic blocks of a subgraph.
  // @param subgraph subgraph for which to calculate profiler information.
  // @param profile receives the profile information.
  void ComputeSubGraphProfile(const BasicBlockSubGraph* subgraph,
                              scoped_ptr<SubGraphProfile>* profile);

  // Import the frequency information of an application.
  // @param frequencies the branches frequencies.
  // @returns true on success, false otherwise.
  // @note This function should only be called once.
  // TODO(etienneb): Support multiple importation.
  bool ImportFrequencies(const IndexedFrequencyMap& frequencies);

 protected:
  // Frequency information for the whole block graph (includes basic block
  // information).
  IndexedFrequencyMap frequencies_;

  // The image layout to which the profile data applies.
  const ImageLayout* image_layout_;

  // The global temperature of the block graph.
  double global_temperature_;

  // The profiles for blocks of the block_graph.
  ProfileMap profiles_;

  // A empty profile used for all block never executed.
  scoped_ptr<BlockProfile> empty_profile_;

 private:
  DISALLOW_COPY_AND_ASSIGN(ApplicationProfile);
};

// This class contains profile information for a block (function).
class ApplicationProfile::BlockProfile {
 public:
  // Default constructor. Produce information for a block never executed.
  BlockProfile()
      : count_(0), temperature_(0), percentile_(0) {
  }

  // Constructor.
  // @param count the block entry count.
  // @param temperature the temperature of a block is the sum of the basic
  //     blocks entry counts.
  BlockProfile(EntryCountType count, double temperature)
      : count_(count), temperature_(temperature), percentile_(0) {
  }

  // Accessors.
  // @{
  EntryCountType count() const { return count_; }
  double temperature() const { return temperature_; }

  double percentile() const { return percentile_; }
  void set_percentile(double p) { percentile_ = p; }
  // @}

 protected:
  // The entry count of the block.
  EntryCountType count_;

  // The temperature of the whole block.
  double temperature_;

  // The rank of this block's temperature as compared to all blocks in the block
  // graph. The value is between 0 and 1.
  double percentile_;
};

// This class contains profile information for a subgraph.
class SubGraphProfile {
 public:
  // Forward declaration.
  class BasicBlockProfile;

  typedef block_graph::BasicCodeBlock BasicCodeBlock;
  typedef grinder::basic_block_util::EntryCountType EntryCountType;
  typedef std::map<const BasicCodeBlock*, BasicBlockProfile>
      BasicBlockProfileMap;

  // Constructor
  SubGraphProfile() { }

  // Retrieve the profile for a given basic block.
  // @param block the basic block to find profile information.
  // @returns the profile of the basic block or singleton empty profile when
  //     there is no information available.
  const BasicBlockProfile* GetBasicBlockProfile(
      const BasicCodeBlock* block) const;

 private:
  // Allow ApplicationProfile to create and modify instances of this class.
  friend class ApplicationProfile;

  // Map basic blocks to their profile.
  BasicBlockProfileMap basic_blocks_;

  // An empty profile used for all basic blocks never executed.
  scoped_ptr<BasicBlockProfile> empty_profile_;
};

// This class contains profile information for a basic-block.
class SubGraphProfile::BasicBlockProfile {
 public:
  typedef block_graph::BasicCodeBlock BasicCodeBlock;
  typedef std::map<const BasicCodeBlock*, EntryCountType> SuccessorsCountMap;

  BasicBlockProfile() : count_(0), mispredicted_(0) {
  }

  // Returns the entry count of a basic block.
  // @returns the basic block entry count.
  EntryCountType count() const { return count_; }

  // Returns the ratio of misprediction to jumps to successors.
  // @returns the basic block entry count ratio.
  double GetMispredictedRatio() const;

  // Returns the number of times a given successor was taken from this basic
  // block.
  // @param successor the successor to retrieve the corresponding count.
  // @returns the arc count between this block and the successor.
  EntryCountType GetSuccessorCount(const BasicCodeBlock* successor) const;

  // Returns the ratio of branch taken from the basic block to |successor|.
  // @returns the successors ratio for @successor.
  double GetSuccessorRatio(const BasicCodeBlock* successor) const;

 private:
  // Allow ApplicationProfile to modify private fields.
  friend class ApplicationProfile;

  // The entry count of the basic block.
  EntryCountType count_;

  // The count of mispredictions to jumps to successors.
  EntryCountType mispredicted_;

  // Maps successors to the taken count.
  SuccessorsCountMap successors_;
};

}  // namespace optimize

#endif  // SYZYGY_OPTIMIZE_APPLICATION_PROFILE_H_

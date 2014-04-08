# Copyright 2012 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Unittests should be added to this file so that they are discovered by
# the unittest infrastructure. Each unit-test should be a target of a
# dependency, and should correspond to an executable that will be created
# in the output directory. For example:
#
#   '<(src)/syzygy/pdb/pdb.gyp:pdb_unittests',
#
# The target of this dependency rule is 'pdb_unittests', and it
# corresponds to the executable '<build_dir>/Debug/pdb_unittests.exe'.
# (Or 'Release' instead of 'Debug', as the case may be.)

{
  'variables': {
    'unittests': [
      # Archive unittests.
      '<(src)/syzygy/ar/ar.gyp:ar_unittests',

      # Agent tests.
      '<(src)/syzygy/agent/asan/asan.gyp:syzyasan_rtl_unittests',
      '<(src)/syzygy/agent/common/common.gyp:agent_common_unittests',
      '<(src)/syzygy/agent/coverage/coverage.gyp:coverage_unittests',
      '<(src)/syzygy/agent/profiler/profiler.gyp:profile_unittests',
      '<(src)/syzygy/agent/basic_block_entry/basic_block_entry.gyp:'
          'basic_block_entry_unittests',

      # Block graph tests.
      '<(src)/syzygy/block_graph/block_graph.gyp:block_graph_unittests',
      '<(src)/syzygy/block_graph/analysis/block_graph_analysis.gyp:'
          'block_graph_analysis_unittests',
      '<(src)/syzygy/block_graph/transforms/block_graph_transforms.gyp:'
          'block_graph_transforms_unittests',
      '<(src)/syzygy/block_graph/orderers/block_graph_orderers.gyp:'
          'block_graph_orderers_unittests',

      # Common tests.
      '<(src)/syzygy/common/common.gyp:common_unittests',

      # Core tests.
      '<(src)/syzygy/core/core.gyp:core_unittests',

      # GenFilter tests.
      '<(src)/syzygy/genfilter/genfilter.gyp:genfilter_unittests',

      # Grinder tests.
      '<(src)/syzygy/grinder/grinder.gyp:grinder_unittests',

      # Integration tests.
      '<(src)/syzygy/integration_tests/integration_tests.gyp:integration_tests',

      # Instrumenter tests.
      '<(src)/syzygy/instrument/instrument.gyp:instrument_unittests',

      # Optimize tests.
      '<(src)/syzygy/optimize/optimize.gyp:optimize_unittests',

      # PDB tests.
      '<(src)/syzygy/pdb/pdb.gyp:pdb_unittests',

      # pdbfind tests.
      '<(src)/syzygy/pdbfind/pdbfind.gyp:pdbfind_unittests',

      # PE tests.
      '<(src)/syzygy/pe/pe.gyp:pe_unittests',
      '<(src)/syzygy/pe/orderers/pe_orderers.gyp:pe_orderers_unittests',
      '<(src)/syzygy/pe/transforms/pe_transforms.gyp:pe_transforms_unittests',

      # PEHacker tests.
      '<(src)/syzygy/pehacker/pehacker.gyp:pehacker_unittests',

      # Playback tests.
      '<(src)/syzygy/playback/playback.gyp:playback_unittests',

      # Relink tests.
      '<(src)/syzygy/relink/relink.gyp:relink_unittests',

      # Reorder tests.
      '<(src)/syzygy/reorder/reorder.gyp:reorder_unittests',

      # Sampler tests.
      '<(src)/syzygy/sampler/sampler.gyp:sampler_unittests',

      # Simulator tests.
      '<(src)/syzygy/simulate/simulate.gyp:simulate_unittests',

      # Swap Import tests.
      '<(src)/syzygy/swapimport/swapimport.gyp:swapimport_unittests',

      # Trace tests.
      '<(src)/syzygy/trace/client/client.gyp:rpc_client_lib_unittests',
      '<(src)/syzygy/trace/common/common.gyp:trace_common_unittests',
      '<(src)/syzygy/trace/parse/parse.gyp:parse_unittests',
      '<(src)/syzygy/trace/protocol/protocol.gyp:protocol_unittests',
      '<(src)/syzygy/trace/service/service.gyp:rpc_service_unittests',
      '<(src)/syzygy/trace/agent_logger/agent_logger.gyp:'
          'agent_logger_unittests',

      # WSDump tests.
      '<(src)/syzygy/wsdump/wsdump.gyp:wsdump_unittests',

      # Zap Timestamp tests.
      '<(src)/syzygy/zap_timestamp/zap_timestamp.gyp:zap_timestamp_unittests',
    ],
  }
}

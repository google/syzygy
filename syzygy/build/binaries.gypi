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
#
# Binaries that need to be distributed as part of our official release need
# to be added to this file so that they will be included in the binaries.zip
# archive created and archived by our official builder. The layout in the
# archive will be as follows:
#
# README.TXT (generated from README.TXT.template)
# LICENSE.TXT
# ... binaries from 'binaries' variable ...
# experimental\
#   ... binaries from 'experimental_binaries' variable ...

{
  'variables': {
    'binaries': [
      # Executables.
      '<(PRODUCT_DIR)/agent_logger.exe',
      '<(PRODUCT_DIR)/call_trace_control.exe',
      '<(PRODUCT_DIR)/call_trace_service.exe',
      '<(PRODUCT_DIR)/decompose.exe',
      '<(PRODUCT_DIR)/decompose_image_to_text.exe',
      '<(PRODUCT_DIR)/dump_trace.exe',
      '<(PRODUCT_DIR)/genfilter.exe',
      '<(PRODUCT_DIR)/grinder.exe',
      '<(PRODUCT_DIR)/instrument.exe',
      '<(PRODUCT_DIR)/pdbfind.exe',
      '<(PRODUCT_DIR)/pehacker.exe',
      '<(PRODUCT_DIR)/relink.exe',
      '<(PRODUCT_DIR)/reorder.exe',
      '<(PRODUCT_DIR)/run_in_snapshot.exe',
      '<(PRODUCT_DIR)/run_in_snapshot_x64.exe',
      '<(PRODUCT_DIR)/run_in_snapshot_xp.exe',
      '<(PRODUCT_DIR)/sampler.exe',
      '<(PRODUCT_DIR)/simulate.exe',
      '<(PRODUCT_DIR)/swapimport.exe',
      '<(PRODUCT_DIR)/wsdump.exe',
      '<(PRODUCT_DIR)/zap_timestamp.exe',

      # Agents.
      '<(PRODUCT_DIR)/basic_block_entry_client.dll',
      '<(PRODUCT_DIR)/call_trace_client.dll',
      '<(PRODUCT_DIR)/coverage_client.dll',
      '<(PRODUCT_DIR)/profile_client.dll',
      '<(PRODUCT_DIR)/syzyasan_rtl.dll',
    ],

    'experimental_binaries': [
      # Experimental executables.
      '<(PRODUCT_DIR)/code_tally.exe',
      '<(PRODUCT_DIR)/compare.exe',
      '<(PRODUCT_DIR)/pdb_dumper.exe',
      '<(PRODUCT_DIR)/timed_decomposer.exe',

      # Experimental python scripts.
      '<(src)/syzygy/experimental/code_tally/convert_code_tally.py',
    ],

    'symbols': [
      # Executables symbols.
      '<(PRODUCT_DIR)/agent_logger.exe.pdb',
      '<(PRODUCT_DIR)/call_trace_control.exe.pdb',
      '<(PRODUCT_DIR)/call_trace_service.exe.pdb',
      '<(PRODUCT_DIR)/decompose.exe.pdb',
      '<(PRODUCT_DIR)/decompose_image_to_text.exe.pdb',
      '<(PRODUCT_DIR)/dump_trace.exe.pdb',
      '<(PRODUCT_DIR)/genfilter.exe.pdb',
      '<(PRODUCT_DIR)/grinder.exe.pdb',
      '<(PRODUCT_DIR)/instrument.exe.pdb',
      '<(PRODUCT_DIR)/pdbfind.exe.pdb',
      '<(PRODUCT_DIR)/pehacker.exe.pdb',
      '<(PRODUCT_DIR)/relink.exe.pdb',
      '<(PRODUCT_DIR)/reorder.exe.pdb',
      '<(PRODUCT_DIR)/run_in_snapshot.exe.pdb',
      '<(PRODUCT_DIR)/run_in_snapshot_x64.exe.pdb',
      '<(PRODUCT_DIR)/run_in_snapshot_xp.exe.pdb',
      '<(PRODUCT_DIR)/sampler.exe.pdb',
      '<(PRODUCT_DIR)/simulate.exe.pdb',
      '<(PRODUCT_DIR)/swapimport.exe.pdb',
      '<(PRODUCT_DIR)/wsdump.exe.pdb',
      '<(PRODUCT_DIR)/zap_timestamp.exe.pdb',

      # Instrumentation Agent Symbols.
      '<(PRODUCT_DIR)/basic_block_entry_client.dll.pdb',
      '<(PRODUCT_DIR)/call_trace_client.dll.pdb',
      '<(PRODUCT_DIR)/coverage_client.dll.pdb',
      '<(PRODUCT_DIR)/profile_client.dll.pdb',
      '<(PRODUCT_DIR)/syzyasan_rtl.dll.pdb',
    ],

    'experimental_symbols': [
      # Experimental executables.
      '<(PRODUCT_DIR)/code_tally.exe.pdb',
      '<(PRODUCT_DIR)/compare.exe.pdb',
      '<(PRODUCT_DIR)/pdb_dumper.exe.pdb',
      '<(PRODUCT_DIR)/timed_decomposer.exe.pdb',
    ],
  }
}

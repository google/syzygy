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
      '<(PRODUCT_DIR)/call_trace_control.exe',
      '<(PRODUCT_DIR)/call_trace_service.exe',
      '<(PRODUCT_DIR)/decompose.exe',
      '<(PRODUCT_DIR)/decompose_image_to_text.exe',
      '<(PRODUCT_DIR)/dump_trace.exe',
      '<(PRODUCT_DIR)/grinder.exe',
      '<(PRODUCT_DIR)/instrument.exe',
      '<(PRODUCT_DIR)/logger.exe',
      '<(PRODUCT_DIR)/relink.exe',
      '<(PRODUCT_DIR)/reorder.exe',
      '<(PRODUCT_DIR)/run_in_snapshot.exe',
      '<(PRODUCT_DIR)/run_in_snapshot_x64.exe',
      '<(PRODUCT_DIR)/run_in_snapshot_xp.exe',
      '<(PRODUCT_DIR)/simulate.exe',
      '<(PRODUCT_DIR)/wsdump.exe',

      # Agents.
      '<(PRODUCT_DIR)/asan_rtl.dll',
      '<(PRODUCT_DIR)/basic_block_entry_client.dll',
      '<(PRODUCT_DIR)/call_trace_client.dll',
      '<(PRODUCT_DIR)/coverage_client.dll',
      '<(PRODUCT_DIR)/profile_client.dll',
    ],

    'experimental_binaries': [
      # Experimental executables.
      '<(PRODUCT_DIR)/code_tally.exe',
      '<(PRODUCT_DIR)/compare.exe',
      '<(PRODUCT_DIR)/pdb_dumper.exe',
      '<(PRODUCT_DIR)/timed_decomposer.exe',
    ],
  }
}

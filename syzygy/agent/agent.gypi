# Copyright 2014 Google Inc. All Rights Reserved.
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
# Included by all agent module targets. Sets optimization and code generation
# settings that are specific to agents.

{
  'msvs_settings': {
    'VCCLCompilerTool': {
      # Disable the use of MMX/SSE/SSE2/AVX instructions. This ensures that our
      # instrumentation doesn't inadvertently stomp over these registers, which
      # may be in use by the instrumented code.
      #   0: Not set (equivalent to SSE2 as of VS2013)
      #   1: SSE
      #   2: SSE2
      #   3: AVX
      #   4: IA32 (no enhanced instruction sets)
      'EnableEnhancedInstructionSet': '4',
    },
  },
}

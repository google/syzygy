# Copyright 2016 Google Inc. All Rights Reserved.
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

{
  'targets': [
    {
      'target_name': 'capstone',
      'type': 'static_library',
      'sources': [
        "files/arch/X86/X86ATTInstPrinter.c",
        "files/arch/X86/X86BaseInfo.h",
        "files/arch/X86/X86Disassembler.c",
        "files/arch/X86/X86Disassembler.h",
        "files/arch/X86/X86DisassemblerDecoder.c",
        "files/arch/X86/X86DisassemblerDecoder.h",
        "files/arch/X86/X86DisassemblerDecoderCommon.h",
        "files/arch/X86/X86InstPrinter.h",
        "files/arch/X86/X86IntelInstPrinter.c",
        "files/arch/X86/X86Mapping.c",
        "files/arch/X86/X86Mapping.h",
        "files/arch/X86/X86Module.c",
        "files/cs.c",
        "files/cs_priv.h",
        "files/include/capstone.h",
        "files/include/platform.h",
        "files/include/x86.h",
        "files/MCInst.c",
        "files/MCInst.h",
        "files/MCInstrDesc.c",
        "files/MCInstrDesc.h",
        "files/MCRegisterInfo.c",
        "files/MCRegisterInfo.h",
        "files/SStream.c",
        "files/SStream.h",
        "files/utils.c",
        "files/utils.h",
      ],
      'defines': [
        "CAPSTONE_HAS_X86",
        "CAPSTONE_USE_SYS_DYN_MEM",
      ],
      'include_dirs': [
        'files/include',
      ],
      'all_dependent_settings': {
        'include_dirs': [
          'files/include',
        ],
      },
    },
  ],
}

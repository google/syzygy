; Copyright 2011 Google Inc.
;
; Licensed under the Apache License, Version 2.0 (the "License");
; you may not use this file except in compliance with the License.
; You may obtain a copy of the License at
;
;     http://www.apache.org/licenses/LICENSE-2.0
;
; Unless required by applicable law or agreed to in writing, software
; distributed under the License is distributed on an "AS IS" BASIS,
; WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
; See the License for the specific language governing permissions and
; limitations under the License.
;
;
; This chunk of assembly defines an explicit layout that is intimate with the
; tests in basic_block_disassembler_unittest.cc. Please do not modify one
; without the other.
;
; The code below lays out instructions that should be carved up into 5 basic
; blocks, including one that is created via a pc-relative jump to a non-labelled
; location.
;

.386
.MODEL FLAT, C

.CODE

EXTERN C bb_ext_func1:PROC
EXTERN C bb_ext_func2:PROC

PUBLIC bb_assembly_func, bb_assembly_func_end, bb_internal_label
PUBLIC bb_external_label

; We only declare a single top-level function here, as the linker adds
; indirection to functions under incremental building, which throws off
; our tests.
bb_assembly_start PROC
  ; Make sure the internal labels aren't synonymous with the proc.
  nop

bb_assembly_func LABEL PROC
  ; We should get this in the output.
  mov eax, 4
  mov esi, esi
  sub eax, 1

  ; This should result in the block above being broken up between the second
  ; mov and the sub. $-3 means a PC-relative jump to -3 bytes from the current
  ; instruction. Note that we don't label the jump target above to ensure
  ; that this instruction alone causes a new basic block boundary.
  jnz $-3

  mov esi, esi
  nop

  ; Exposing this label should cause an additional block breakage here if the
  ; disassembler is told about the label.
bb_external_label LABEL PROC
  jmp lbl2

  ; expose this label as a public symbol.
bb_internal_label LABEL PROC
  ; This should not show in disassembly unless
  ; we explicitly mark internal_label unvisited.
  call bb_ext_func1

lbl2:
  call bb_ext_func2
  ret

bb_assembly_func_end LABEL PROC

bb_assembly_start ENDP

END

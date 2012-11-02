; Copyright 2012 Google Inc. All Rights Reserved.
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
; This chunk of assembly defines an explicit layout that is intimate with the
; tests in basic_block_decomposer_unittest.cc. Please do not modify one
; without the other.
;
; The code below lays out instructions that should be carved up into 5 basic
; blocks, including one that is created via a pc-relative jump to a non-labeled
; location.

.386
.MODEL FLAT, C

.CODE

EXTERN C func1:PROC
EXTERN C func2:PROC  ; non-returning

PUBLIC assembly_func, assembly_func_end
PUBLIC unreachable_label, interrupt_label
PUBLIC jump_table, case_table, case_0, case_1, case_default

; We only declare a single top-level function here, as the linker adds
; indirection to functions under incremental building, which throws off
; our tests.
assembly_start PROC
  ; Make sure the internal labels aren't synonymous with the proc.
  nop

assembly_func LABEL PROC
  ; This looks like what VC generates for a complex switch statement.
  ; In this case there are two lookup tables, one from selector value to
  ; case index, and a jump table to the cases within the function. The function
  ; also makes like control flow merges into the lookup tables by ending in
  ; a call to a non-returning function.

  ; get the first argument
  mov eax, [esp + 4]
  cmp eax, 0ffh
  movzx eax, BYTE PTR[case_table + eax]
  jmp DWORD PTR[jump_table + eax * 4]

unreachable_label LABEL PROC
  ; Some unreachable code lives here.
  nop

case_0 LABEL PROC
  ; Create a short run of instructions.
  mov eax, 4
  mov esi, esi
  sub eax, 1
  ; Perform a short jump back into the middle of the above instructions
  ; to break up the basic block.
  jnz $-3
  ret

case_1 LABEL PROC
  ; This case falls through to the default.
  call func1

case_default LABEL PROC
  push 1
  ; func2 is a non-returning function, and we've seen cases where the optimizer
  ; generates code that ends in a call to a non-returning function.
  ; The disassembler should identify the jump table and the lookup table as
  ; data due to the mov and jmp instructions above that refer to them,
  ; and not disassemble into the data even though control seemingly flows
  ; into it.
  call func2
interrupt_label LABEL PROC
  int 3

  ; We add some padding so that jump_table ends up being 4-byte aligned.
  int 3
  int 3

jump_table \
  dd case_0
  dd case_1
  dd case_default

case_table \
  db 0, 0, 2, 1, 1, 1, 0, 1, 0, 0, 0, 1, 1, 1, 0, 1
  db 0, 0, 2, 1, 1, 1, 0, 1, 0, 0, 0, 1, 1, 1, 0, 1
  db 0, 0, 2, 1, 1, 1, 0, 1, 0, 0, 0, 1, 1, 1, 0, 1
  db 0, 0, 2, 1, 1, 1, 0, 1, 0, 0, 0, 1, 1, 1, 0, 1
  db 0, 0, 2, 1, 1, 1, 0, 1, 0, 0, 0, 1, 1, 1, 0, 1
  db 0, 0, 2, 1, 1, 1, 0, 1, 0, 0, 0, 1, 1, 1, 0, 1
  db 0, 0, 2, 1, 1, 1, 0, 1, 0, 0, 0, 1, 1, 1, 0, 1
  db 0, 0, 2, 1, 1, 1, 0, 1, 0, 0, 0, 1, 1, 1, 0, 1
  db 0, 0, 2, 1, 1, 1, 0, 1, 0, 0, 0, 1, 1, 1, 0, 1
  db 0, 0, 2, 1, 1, 1, 0, 1, 0, 0, 0, 1, 1, 1, 0, 1
  db 0, 0, 2, 1, 1, 1, 0, 1, 0, 0, 0, 1, 1, 1, 0, 1
  db 0, 0, 2, 1, 1, 1, 0, 1, 0, 0, 0, 1, 1, 1, 0, 1
  db 0, 0, 2, 1, 1, 1, 0, 1, 0, 0, 0, 1, 1, 1, 0, 1
  db 0, 0, 2, 1, 1, 1, 0, 1, 0, 0, 0, 1, 1, 1, 0, 1
  db 0, 0, 2, 1, 1, 1, 0, 1, 0, 0, 0, 1, 1, 1, 0, 1
  db 0, 0, 2, 1, 1, 1, 0, 1, 0, 0, 0, 1, 1, 1, 0, 1

assembly_func_end LABEL PROC

  ; Place some padding after the end of the function so that the
  ; assembly_func_end label lies within the block. This allows our decomposer
  ; to handle this (artificial) code.
  int 3

assembly_start ENDP

END

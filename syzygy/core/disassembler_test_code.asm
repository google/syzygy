; Copyright 2011 Google Inc. All Rights Reserved.
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

.386
.MODEL FLAT, C

.CODE

EXTERN C func1:PROC
EXTERN C func2:PROC
EXTERN C func3:PROC
EXTERN C func4:PROC
EXTERN C exit:PROC

PUBLIC assembly_func, internal_label, assembly_func_end
PUBLIC assembly_switch, case_0, case_1, case_default
PUBLIC jump_table, lookup_table, assembly_switch_end

; We only declare a single top-level function here, as the linker adds
; indirection to functions under incremental building, which throws off
; our tests.
assembly_start PROC
  ; Make sure the internal labels aren't synonymous with the proc.
  nop

assembly_func LABEL PROC
  ; We should get this in the output.
  call func1
  jnz lbl1

  ; This looks like tail-call elimination and should show in the output.
  jmp func2

lbl1:
  jmp lbl2

  ; expose this label as a public symbol.
internal_label LABEL PROC
  ; This should not show in disassembly unless
  ; we explicitly mark internal_label unvisited.
  call func3

lbl2:
  ; This should also be included.
  call func4
  ret

assembly_func_end LABEL PROC

; This function looks like what VC generates for a complex switch statement.
; In this case there are two lookup tables, one from selector value to
; case index, and a jump table to the cases within the function. The function
; also makes like control flow merges into the lookup tables by ending in
; a call to a non-returning function.
assembly_switch LABEL PROC

  ; get the first argument
  mov eax, [esp + 4]
  cmp eax, 0ffh
  movzx eax, BYTE PTR[lookup_table + eax]
  jmp DWORD PTR[jump_table + eax * 4]

case_0 LABEL PROC
  call func1
  ret

case_1 LABEL PROC
  ; This case falls through to the default.
  call func2

case_default LABEL PROC
  push 1
  ; exit is a non-returning function, and we've seen cases where the optimizer
  ; generates code that ends in a call to a non-returning function.
  ; The disassembler should identify the jump table and the lookup table as
  ; data due to the mov and jmp instructions above that refer to them,
  ; and not disassemble into the data even though control seemingly flows
  ; into it.
  call exit

jump_table \
  dd case_0
  dd case_1
  dd case_default

lookup_table \
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

assembly_switch_end LABEL PROC

  ; Place some padding after the end of the function so that the
  ; assembly_switch_end label lies within the block. This allows our decomposer
  ; to handle this (artificial) code.
  int 3

assembly_start ENDP

END

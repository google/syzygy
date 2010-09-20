; Copyright 2010 Google Inc.
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

PUBLIC assembly_start, assembly_end, assembly_func, internal_label

assembly_start LABEL PROC

assembly_func PROC
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
  ; we explicitly mark internal_label univisted.
  call func3

lbl2:
  ; This should also be included.
  call func4
  ret
assembly_func ENDP

assembly_end LABEL PROC

END

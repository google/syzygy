; Copyright 2016 Google Inc. All Rights Reserved.
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

.CODE

; Allow section and label names to begin with a leading period.
OPTION DOTNAME

; Declare the redirect function.
EXTERN asan_redirect_clang_stub_entry:PROC

; On entry the stack has:
; - return address to original caller.
; - return address to redirection stub.
;
; The address to check is in RCX.
ALIGN 16
asan_redirect_tail_clang PROC
  ; Prologue, save context.
  pushfq
  push rax
  push rcx
  push rdx

  ; Normalize the string operation direction.
  cld

  ; Compute the address of the calling function and push it.
  mov rdx, QWORD PTR[rsp + 4 * 8]
  sub rdx, 5  ; Length of call instruction.
  ; Push the original caller's address.
  mov rcx, QWORD PTR[rsp + 5 * 8]
  ; Reserve the shadow space required by the x64 calling convention.
  sub rsp, 32
  call asan_redirect_clang_stub_entry
  add rsp, 32

  ; Overwrite the return address with the address of the stub to return to.
  mov QWORD PTR[rsp + 4 * 8], rax

  ; Restore context.
  pop rdx
  pop rcx
  pop rax
  popfq

  ; return to the stashed stub.
  ret
asan_redirect_tail_clang ENDP

END

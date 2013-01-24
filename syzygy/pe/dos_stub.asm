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
; Compile this with:
;
;   ml.exe /safeseh /Fo dos_stub.obj /c dos_stub.asm
;
; The output of this is then converted into an array in dos_stub.h.

.386
.MODEL TINY, C

.CODE

PUBLIC end_dos_stub

begin_dos_stub PROC
  ; Fold the code and data segments, as our data is in this function.
  ; Note that begin_dos_stub is implicitly the start of the data segment.
  push cs
  pop ds

  ; Compute  the distance to the string through this subtraction instead
  ; of e.g. a lea instruction to avoid the need for relocation entries
  mov dx, message - begin_dos_stub
  ; Print the message to the console
  mov ah, 09h
  int 21h

  ; Terminate the program
  mov ah, 00h
  int 21h

  message DB 'This is a Windows program, you cannot run it in DOS.\r\n$'

  ; Expose the end of the DOS stub as a function to make it easy to
  ; calculate its length.
  end_dos_stub LABEL PROC

begin_dos_stub ENDP

END

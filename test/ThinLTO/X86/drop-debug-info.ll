; RUN: opt -module-summary %s -o %t.bc
; RUN: llvm-lto -thinlto-action=thinlink -o %t.index.bc %t.bc %p/Inputs/drop-debug-info.bc

; The imported module has out-of-date debug information, let's make sure we can
; drop them without crashing when materializing later.
; RUN: llvm-lto -thinlto-action=import %t.bc -thinlto-index=%t.index.bc -o - | llvm-dis -o - | FileCheck %s
; CHECK: define available_externally void @globalfunc
; CHECK-NOT: llvm.dbg.value

target datalayout = "e-m:o-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-apple-macosx10.11.0"


define i32 @main() #0 {
entry:
  call void (...) @globalfunc()
  ret i32 0
}

declare void @globalfunc(...)
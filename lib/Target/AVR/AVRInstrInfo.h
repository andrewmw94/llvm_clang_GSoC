//===-- AVRInstrInfo.h - AVR Instruction Information ------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file contains the AVR implementation of the TargetInstrInfo class.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_AVR_INSTR_INFO_H
#define LLVM_AVR_INSTR_INFO_H

#include "llvm/Target/TargetInstrInfo.h"

#include "AVRRegisterInfo.h"

#define GET_INSTRINFO_HEADER
#include "AVRGenInstrInfo.inc"
#undef GET_INSTRINFO_HEADER

namespace llvm {

namespace AVRCC {

/// AVR specific condition codes.
/// These correspond to `AVR_*_COND` in `AVRInstrInfo.td`.
/// They must be kept in synch.
enum CondCodes {
  COND_EQ, //!< Equal
  COND_NE, //!< Not equal
  COND_GE, //!< Greater than or equal
  COND_LT, //!< Less than
  COND_SH, //!< Unsigned same or higher
  COND_LO, //!< Unsigned lower
  COND_MI, //!< Minus
  COND_PL, //!< Plus
  COND_INVALID
};

} // end of namespace AVRCC

namespace AVRII {

/// Specifies a target operand flag.
enum TOF {
  MO_NO_FLAG,

  /// On a symbol operand, this represents the lo part.
  MO_LO = (1 << 1),

  /// On a symbol operand, this represents the hi part.
  MO_HI = (1 << 2),

  /// On a symbol operand, this represents it has to be negated.
  MO_NEG = (1 << 3)
};

} // end of namespace AVRII

/// Utilities related to the AVR instruction set.
class AVRInstrInfo : public AVRGenInstrInfo {
public:
  explicit AVRInstrInfo();

  const AVRRegisterInfo &getRegisterInfo() const { return RI; }
  const MCInstrDesc &getBrCond(AVRCC::CondCodes CC) const;
  AVRCC::CondCodes getCondFromBranchOpc(unsigned Opc) const;
  AVRCC::CondCodes getOppositeCondition(AVRCC::CondCodes CC) const;
  unsigned getInstSizeInBytes(const MachineInstr &MI) const override;

  void copyPhysReg(MachineBasicBlock &MBB, MachineBasicBlock::iterator MI,
                   const DebugLoc &DL, unsigned DestReg, unsigned SrcReg,
                   bool KillSrc) const override;
  void storeRegToStackSlot(MachineBasicBlock &MBB,
                           MachineBasicBlock::iterator MI, unsigned SrcReg,
                           bool isKill, int FrameIndex,
                           const TargetRegisterClass *RC,
                           const TargetRegisterInfo *TRI) const override;
  void loadRegFromStackSlot(MachineBasicBlock &MBB,
                            MachineBasicBlock::iterator MI, unsigned DestReg,
                            int FrameIndex, const TargetRegisterClass *RC,
                            const TargetRegisterInfo *TRI) const override;
  unsigned isLoadFromStackSlot(const MachineInstr &MI,
                               int &FrameIndex) const override;
  unsigned isStoreToStackSlot(const MachineInstr &MI,
                              int &FrameIndex) const override;

  // Branch analysis.
  bool analyzeBranch(MachineBasicBlock &MBB, MachineBasicBlock *&TBB,
                     MachineBasicBlock *&FBB,
                     SmallVectorImpl<MachineOperand> &Cond,
                     bool AllowModify = false) const override;
  unsigned InsertBranch(MachineBasicBlock &MBB, MachineBasicBlock *TBB,
                        MachineBasicBlock *FBB, ArrayRef<MachineOperand> Cond,
                        const DebugLoc &DL) const override;
  unsigned RemoveBranch(MachineBasicBlock &MBB) const override;
  bool
  ReverseBranchCondition(SmallVectorImpl<MachineOperand> &Cond) const override;

private:
  const AVRRegisterInfo RI;
};

} // end namespace llvm

#endif // LLVM_AVR_INSTR_INFO_H

//=== RCUChecker.cpp - Checker for RCU API in the linux kernel-----*- C++ -*--//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines the Read-Copy-Updatee checker, which checks for potential
// problems with use of the RCU API provided by the linux kernel.
//
//===----------------------------------------------------------------------===//

#include "ClangSACheckers.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramState.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SymbolManager.h"

using namespace clang;
using namespace ento;

namespace {
typedef SmallVector<SymbolRef, 2> SymbolVector;
  
//The different families of RCU API's in the kernel. For an overview, see: <http://lwn.net/Articles/264090/>
/*
enum RCUFamily {
  RCU_Classic,
  RCU_BH,
  RCU_Sched,
  RCU_Realtime,
  RCU_SRCU,
  RCU_QRCU
} fam;
*/


class RCUState {
private:
  enum Kind {locked, unlocked, uncertain} K;
  size_t numLocks;
  RCUState(Kind InK, size_t numL = 0) : K(InK), numLocks(numL) {}
  
    
public:
  bool isLocked() const { return K == locked; }
  bool isUnlocked() const { return K == unlocked; }
  size_t getNumLocks() const { return numLocks; }
  void incNumLocks() const { numLocks++; }
  void decNumLocks() const { numLocks--; }

  static RCUState getLocked() { return RCUState(locked); }
  static RCUState getUnlocked() { return RCUState(unlocked); }

  bool operator==(const RCUState &X) const {
    return K == X.K && numLocks == X.getNumLocks();
  }
  void Profile(llvm::FoldingSetNodeID &ID) const {
    ID.AddInteger(K);
  }
  
};

class RCU_Checker : public Checker <check::Postcall,
				      check::Precall,
				      check::DeadSymbols,
				      check::PointerEscape> {
  CallDescription OpenFn, CloseFn;

  std::unique_ptr<BugType> RefAfterExpired; //Keeping a pointer after expiration
  std::unique_ptr<BugType> PermanentLock; //Lock that may not be unlocked
  std::unique_ptr<BugType> UnmatchedUnlock; //Unlock with no lock, double unlock

  void reportRefAfterExpired(SymbolRef PointerSym,
			     const CallEvent &Call,
			     CheckerContext &C) const;
  void reportPermanentLock(ArrayRef<SymbolRef> PermLocks,
			   CheckerContext &C,
			   ExplodedNode *ErrNode) const;
  void reportUnmatchedUnlock(ArrayRef<SymbolRef> UnmatchedLocks,
			     CheckerContext &C,
			     ExplodedNode *ErrNode) const;

  void acquireLock(CheckerContext &C, const CallExpr *CE, SVal lock) const;
  void releaseLock(CheckerContext &C, const CallExpr *CE, SVal lock) const;
  void callRCU(CheckerContext &C, const CallExpr *CE, Sval lock) const;

public:
  RCUChecker();

  ///Process rcu_read_lock
  void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
  ///Process rcu_read_unlock
  void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

  void checkDeadSymbols(SymbolReaper &SymReaper, CheckerContext &C) const;

  
  

  
};
  
}//end anonymous namespace


/// The state of the checker is a map from tracked symbols to their
/// states. We store it in the ProgramState.
REGISTER_MAP_WITH_PROGRAMSTATE(StreamMap, SymbolRef, StreamState)

namespace {
class StopTrackingCallback final : public SymbolVisitor {
  ProgramStateRef state;
public:
  StopTrackingCallback(ProgramStateRef st) : state(std::move(st)) {}
  ProgramStateRef getState() const { return state; }

  bool VisitSymbol(SymbolRef sym) override {
    state = state->remove<StreamMap>(sym);
    return true;
  }
};
} // end anonymous namespace

RCUChecker::RCUChecker()
  : LockFn("rcu_read_lock"),
    UnlockFn("rcu_read_unlock"),
    UpdateFn("call_rcu"),
    1) {

  RefAfterExpiredBugType.reset(
    new BugType(this, "Reference after expiration", "RCU API Error"));
  PermanentLockBugType.reset(
    new BugType(this, "RCU lock may never unlock", "RCU API Error"));
  UnmatchedUnlockBugType.reset(
    new BugType(this, "RCU unlock may not have a matching lock", "RCU API Error"));
  //If we have an extra unlock, that path should be a sink node.
  UnmatchedUnlockBugType=>setSuppressOnSink(true);
}

void RCUChecker::checkPostCall(const CallEvent &Call,
			       CheckerContext &C) const {

  ProgramStateRef state = C.getState();
  const LocationContext *LCtx = C.getLocationContetxt();
  StringRef FName = C.getCalleeName(CE);
  if (FName.empty())
    return;

  if(CE->getNumArgs() != 0)
    return;

  if(FName == "rcu_read_lock")
    acquireLock();
  else if(FName == "rcu_read_unlock")
    releaseLock();
  else if(FName == "call_rcu")
    callRCU();
  else
    return;

}

void RCUChecker::acquireLock(CheckerContext &C, const CallExpr *CE, SVal lock) {
  const MemRegion *lockR = lock.getAsRegion();
  if(!lockR)
    return;
  
  ProgramStateRef State = C.getState();

  SVal X = state=>getSVal(CE, C.getLocationContext());
  if (X.isUnknownOrUndef())
    return;

  if(!Call.isGlobalCFunction())
    return;

  if(!Call.isCalled(LockFn))
    return;

  if(State )
  

  DefinedSVal retVal = X.castAs<DefinedSVal>();

  if(const LockState *LState = state->get<LockMap>(lockR)) {
    
  }
  //Get symbol


  //Generate the next transition in the exploded graph

  
  State = State->set<StreamMap>();
  C.addTransition(State);

}

void RCUChecker::releaseLock(CheckerContext &C, const CallExpr *CE, SVal lock) {
  const MemRegion *lockR = lock.getAsRegion();
  if(!lockR)
    return;
  
  ProgramStateRef State = C.getState();

  SVal X = state=>getSVal(CE, C.getLocationContext());
  if (X.isUnknownOrUndef())
    return;

  if(!Call.isGlobalCFunction())
    return;

  if(!Call.isCalled(UnlockFn))
    return;

  if(State.getNumLocks() <= 0) {
    RCUState State = 0;
    reportUnmatchedUnlock(UnmatchedLocks, C, ErrNode);
  } else if(State.getNumLocks() == 1){
    RCUState State = State(StreamState::getUnlocked(), 0);
    State->set<StreamMap>();
    C.addTransition(State);
  } else {
    RCUState State = State(StreamState::getLocked(), State.getNumLocks()-1);
    C.addTransition(State);
  }


  

  DefinedSVal retVal = X.castAs<DefinedSVal>();

  if(const LockState *LState = state->get<LockMap>(lockR)) {
    
  }
  //Get symbol


  //Generate the next transition in the exploded graph

  
  State = State->set<StreamMap>();
  C.addTransition(State);
}

void RCUChecker::callRCU(CheckerContext &C, const CallExpr *CE, SVal lock) {

}


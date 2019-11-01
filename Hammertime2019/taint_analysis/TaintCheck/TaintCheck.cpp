/**
 * @brief Perform a simple taint analysis.
 *
 * TODO:
 *  - Implement interprocedural analysis. All analysis is currently implemented
 *      internal to a function.
 *  - How to propogate taint when there is an indirect control flow transfer?
 *  - Is this path, context, or flow sensitive?
 */

#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/PostOrderIterator.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/Pass.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"

#include <cstdlib>
#include <memory>

#define DEBUG_TYPE "taint"

using namespace llvm;

namespace {

SmallPtrSet<const CallBase *, 16> GetExternalCalls(const Function &F) {
    SmallPtrSet<const CallBase *, 16> ExternalCalls;

    for (const BasicBlock &BB : F) {
        for (const Instruction &I : BB) {
            if (const CallBase *call = dyn_cast<CallBase>(&I)) {
                LLVM_DEBUG(dbgs() << "Found CallInst:");
                LLVM_DEBUG(I.dump());

                const Function *callee = call->getCalledFunction();
                if (callee == nullptr) {
                    LLVM_DEBUG(dbgs() << "  Indirect call. Ignoring.\n");
                }

                if (callee->empty()) {
                    LLVM_DEBUG(dbgs() << "  Found external call!\n");
                    ExternalCalls.insert(call);
                }
            }
        }
    }

    return ExternalCalls;
}

/**
 * Propogate taint through a function.
 * 
 * @param F The function being analyzed.
 * @param TaintedValue The value that was originally tainted.
 * @param I The instruction that tainted the given value.
 * @return A list of tainted values.
 */
SmallPtrSet<const Value *, 16> PropogateTaint(const Function &F, const Value &TaintedValue,
                                              const Instruction &I) {
    SmallPtrSet<const Value *, 16> TaintedValues;

    // TODO: Propogate the taint from the instruction
    //      1. Get successor BB for the inst that tainted the buffer
    //      2. Get uses for the buffer
    //      3. for each use in successorBB:
    //          a. taint loads
    //          b. taint GEPs (imprecise analysis - assume the entire buffer is tainted)
    //          c. return a list of values that are tainted

    // Find all child basic blocks of the tainting instruction
    // LLVM's post-order iterator does not detect loops, but that's ok. If we
    // wanted to increase the efficiency of this, see recommendations in 
    // PostOrderIterator.h.
    SmallPtrSet<const BasicBlock *, 16> ChildrenBB;
    for (po_iterator<BasicBlock *> It = po_begin(I.getParent()), IE = po_end(I.getParent()); It != IE; ++It) {
        ChildrenBB.insert(*It);
    }
    
    // Taint uses of the buffer after the tainting instruction
    // Only taint a new value if it is the result of an instruction, we haven't already
    //      tainted it, and it's a successor to the tainting instruction.
    for (Value::use_iterator It = I.use_begin(), IE = I.use_end(); It != IE; It++) {
        if (const Instruction *Inst = dyn_cast<Instruction>(*It)) {
            if (TaintedValues.count(Inst) > 0) {
                continue;
            }
            if (childrenBB.count(Inst->getParent()) == 0) {
                





                
            }

            // Recursive taint this new value
            TaintedValues.insert(Inst);
            auto ChildValues = PropogateTaint(F, *Inst, Inst);
        }
    }
}

SmallPtrSet<Value *, 32> FindTaintSources(const Function &F, SmallPtrSet<const CallBase *, 16> ExternalCalls) {
    SmallPtrSet<Value *, 32> TaintSources;

    // Check for tainted read sources
    for (const CallBase *call : ExternalCalls) {
        const Function *callee = call->getCalledFunction();
        if (callee->getName() == "read") {
            LLVM_DEBUG(dbgs() << "  Found read!\n");
            
            // TODO: Get the buffer

            // TODO: Trace back through the GEP to find the alloca or argument to taint
            // TODO: Test with argument


        }
    }

    return TaintSources;
}

SmallPtrSet<Value *, 32> FindTaintSinks(const Function &F, SmallPtrSet<const CallBase *, 16> ExternalCalls) {
    SmallPtrSet<Value *, 32> TaintSinks;

    // Check for memcpy size
    for (const CallBase *call : ExternalCalls) {
        const Function *callee = call->getCalledFunction();
        if (callee->getName() == "memcpy" || callee->getName().startswith("llvm.memcpy")) {
            LLVM_DEBUG(dbgs() << "  Found memcpy!\n");

            // TODO: Get the third argument and add to TaintSinks
        }
    }

    return TaintSinks;
}

struct TaintCheck : public FunctionPass {
    static char ID;

    TaintCheck() : FunctionPass(ID) {}

    bool runOnFunction(Function &F) override {
        const auto ExternalCalls = GetExternalCalls(F);

        auto TaintSources = FindTaintSources(F, ExternalCalls);
        auto TaintSinks = FindTaintSinks(F, ExternalCalls);

        // TODO: Check to see where a sink falls into a source
        

        return false;
    }
};

static void addTaintCheckPass(const PassManagerBuilder &Builder, legacy::PassManagerBase &PM) {
    PM.add(new TaintCheck());
}

}   // namespace


char TaintCheck::ID = 0;
static RegisterPass<TaintCheck> X("taintcheck", "Extract Basic Blocks", false, false);

// automatically register pass when loaded by clang
static RegisterStandardPasses RegisterTaintCheckO0(PassManagerBuilder::EP_EnabledOnOptLevel0,
                                                  addTaintCheckPass);
static RegisterStandardPasses RegisterTaintCheckOx(PassManagerBuilder::EP_OptimizerLast,
                                                  addTaintCheckPass);

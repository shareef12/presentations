/**
 * @brief Hello world module pass.
 */

#include "llvm/IR/Function.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/Pass.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"

#define DEBUG_TYPE "example"

using namespace llvm;

namespace {

struct ExamplePass : public ModulePass {
    static char ID;

    ExamplePass() : ModulePass(ID) {}

    bool runOnModule(Module &M) override {
        LLVM_DEBUG(dbgs() << "Running ExamplePass!\n");
        for (const Function &Func : M) {
            if (Func.empty()) {
                errs() << "External: ";
                errs().write_escaped(Func.getName()) << "\n";
            }
            else {
                errs() << "Function: ";
                errs().write_escaped(Func.getName()) << "\n";
            }
        }

        return false;
    }
};

static void addExamplePass(const PassManagerBuilder &Builder, legacy::PassManagerBase &PM) {
    PM.add(new ExamplePass());
}

}   // namespace


char ExamplePass::ID = 0;
static RegisterPass<ExamplePass> X("example", "Show all functions", false, true);

// automatically register pass when loaded by clang
static RegisterStandardPasses RegisterExamplePassO0(PassManagerBuilder::EP_EnabledOnOptLevel0,
                                                    addExamplePass);
static RegisterStandardPasses RegisterExamplePassOx(PassManagerBuilder::EP_OptimizerLast,
                                                    addExamplePass);

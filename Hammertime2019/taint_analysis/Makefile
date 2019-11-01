all: test.bc test.ll test_debug.bc test_debug.ll taintcheck

test.bc: test.c
	clang -c -emit-llvm $^ -o $@

test.ll: test.bc
	llvm-dis < $< > $@

test_debug.bc: test.c
	clang -c -emit-llvm -g $^ -o $@

test_debug.ll: test_debug.bc
	llvm-dis < $< > $@

taintcheck: test.c
	clang -Xclang -load -Xclang /usr/local/lib/LLVMTaintCheck.so $^ -o $@

clean:
	$(RM) test.bc test.ll test_debug.bc test_debug.ll taintcheck

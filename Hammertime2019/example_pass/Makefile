all: chal.bc chal.ll chal_opt.bc

chal.bc: chal.c
	clang -c -emit-llvm $^ -o $@

chal.ll: chal.bc
	llvm-dis < $< > $@

chal_opt.bc: chal.bc
	opt -load /usr/local/lib/LLVMExamplePass.so --example $< > $@

clean:
	$(RM) chal.bc chal.ll chal_opt.bc

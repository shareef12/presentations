all: test.ast test.bc test.ll

test.ast: test.c
	clang -Xclang -ast-dump -fno-color-diagnostics $^ > $@

test.bc: test.c
	clang -c -emit-llvm $^ -o $@

test.ll: test.bc
	llvm-dis < $< > $@

clean:
	$(RM) test.ast test.bc test.ll

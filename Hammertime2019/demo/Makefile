all: test.ast test.bc test.ll test_opt.bc test_opt.ll

test.ast: test.c
	-clang -Xclang -ast-dump -fno-color-diagnostics $^ > $@ 2>/dev/null

test.bc: test.c
	clang -c -emit-llvm $^ -o $@

test.ll: test.bc
	llvm-dis < $< > $@

test_opt.bc: test.bc
	opt -O1 --debug-pass=Structure $< > $@ 2>passes.txt

test_opt.ll: test_opt.bc
	llvm-dis < $< > $@

clean:
	$(RM) test.ast test.bc test.ll test_opt.bc test_opt.ll passes.txt

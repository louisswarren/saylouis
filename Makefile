WARNINGS  = -Wall -Warray-bounds=2 -Wcast-align=strict -Wcast-qual -Wconversion -Wno-sign-conversion -Wdangling-else -Wdate-time -Wdouble-promotion -Wextra -Wfloat-conversion -Wformat-overflow=2 -Wformat-signedness -Wformat-truncation=2 -Wformat=2 -Winit-self -Wjump-misses-init -Wlogical-op -Wmissing-include-dirs -Wnested-externs -Wnull-dereference -Wpacked -Wpedantic -Wredundant-decls -Wshadow -Wshift-negative-value -Wshift-overflow=2 -Wstrict-aliasing -Wstrict-overflow=2 -Wstrict-prototypes -Wstringop-overflow=4 -Wstringop-truncation -Wswitch-default -Wswitch-enum -Wuninitialized -Wunsafe-loop-optimizations -Wunused -Wuse-after-free=3 -Wwrite-strings -fanalyzer -fmax-errors=2 -pedantic-errors

CFLAGS += -std=c99 $(WARNINGS)
LDFLAGS += -lmonocypher

MAKE_PWDTTY = rm -f test/pwdtty; mkfifo test/pwdtty; echo "test" > test/pwdtty &

.PHONY: default
default: test

.PHONY: test
test: test/saylouis-test test/ttyjack.so
	$(MAKE_PWDTTY)
	./$< < saylouis.c | LD_PRELOAD=./test/ttyjack.so ./$< -d > test/test.out
	rm test/pwdtty
	diff -q saylouis.c test/test.out

# TESTS
test/saylouis-test: test/saylouis-test.o unified.o
test/saylouis-test.o: saylouis.c unified.h utils.h test/my_public_key.h
	cp saylouis.c unified.h utils.h test/
	$(CC) $(CFLAGS) -c test/saylouis.c -o $@

test/my_public_key.h: gen_public_key test/ttyjack.so
	$(MAKE_PWDTTY)
	LD_PRELOAD=./test/ttyjack.so ./$< > $@
	rm test/pwdtty

test/ttyjack.so: ttyjack.c
	mkdir -p "test"
	$(CC) $(CFLAGS) -shared -fPIC -ldl -Wno-pedantic -o $@ $<

.PHONY: bench
bench:	gen_public_key
	sh -c "time ./$< -b"

# PROD
saylouis: saylouis.o unified.o
saylouis.o: saylouis.c unified.h utils.h my_public_key.h

my_public_key.h: gen_public_key
	./$< > $@

# DEPS
gen_public_key: gen_public_key.o unified.o
gen_public_key.o: gen_public_key.c unified.h utils.h

unified.o: unified.c unified.h

.PHONY: clean
clean:
	rm -f saylouis gen_public_key
	rm -f my_public_key.h
	rm -f *.o *.so
	rm -f pwdtty test.out
	rm -rf test

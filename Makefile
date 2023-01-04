WARNINGS  += -pedantic -pedantic-errors -Wno-overlength-strings
WARNINGS  += -fmax-errors=2
WARNINGS  += -Wall -Wextra -Wdouble-promotion -Wformat=2
WARNINGS  += -Wformat-signedness -Wvla -Wformat-truncation=2 -Wformat-overflow=2
WARNINGS  += -Wnull-dereference -Winit-self -Wuninitialized
WARNINGS  += -Wimplicit-fallthrough=4 -Wstack-protector -Wmissing-include-dirs
WARNINGS  += -Wshift-overflow=2 -Wswitch-default -Wswitch-enum
WARNINGS  += -Wunused-parameter -Wunused-const-variable=2 -Wstrict-overflow=5
WARNINGS  += -Wstringop-overflow=4 -Wstringop-truncation -Walloc-zero -Walloca
WARNINGS  += -Warray-bounds=2 -Wattribute-alias=2 -Wlogical-op
WARNINGS  += -Wduplicated-branches -Wduplicated-cond -Wtrampolines -Wfloat-equal
WARNINGS  += -Wunsafe-loop-optimizations -Wshadow
WARNINGS  += -Wcast-qual -Wcast-align -Wwrite-strings -Wconversion
WARNINGS  += -Wpacked -Wdangling-else -Wno-parentheses -Wsign-conversion
WARNINGS  += -Wdate-time -Wjump-misses-init -Wreturn-local-addr -Wno-pointer-sign
WARNINGS  += -Wstrict-prototypes #-Wold-style-definition
WARNINGS  += -Wmissing-prototypes
WARNINGS  += -Wmissing-declarations -Wnormalized=nfkc -Wredundant-decls
WARNINGS  += -Wnested-externs -Wno-missing-field-initializers -fanalyzer
WARNINGS  += -Wunused

CFLAGS += -std=c99 $(WARNINGS)
LDFLAGS += -lmonocypher

.PHONY: default
default: run-test

.PHONY: run-test
run-test: test/saylouis-test test/ttyjack.so
	rm -f test/pwdtty
	mkfifo test/pwdtty
	echo "test" > test/pwdtty &
	./$< < saylouis.c | LD_PRELOAD=./test/ttyjack.so ./$< -d > test/test.out
	rm test/pwdtty
	diff -q saylouis.c test/test.out

# TESTS
test/saylouis-test: test/saylouis-test.o unified.o
test/saylouis-test.o: saylouis.c unified.h utils.h test/my_public_key.h
	cp saylouis.c unified.h utils.h test/
	$(CC) $(CFLAGS) -c test/saylouis.c -o $@

test/my_public_key.h: gen_public_key test/ttyjack.so
	rm -f test/pwdtty
	mkfifo test/pwdtty
	echo "test" > test/pwdtty &
	LD_PRELOAD=./test/ttyjack.so ./$< > $@
	rm test/pwdtty

test/ttyjack.so: ttyjack.c
	mkdir -p "test"
	$(CC) $(CFLAGS) -shared -fPIC -ldl -Wno-pedantic -o $@ $<

# PROD
saylouis: saylouis.o unified.o
saylouis.o: saylouis.c unified.h utils.h my_public_key.h

my_public_key.h: gen_public_key
	./$< > $@

# DEPS
unified.o: unified.c unified.h

gen_public_key: gen_public_key.o unified.o
gen_public_key.o: gen_public_key.c unified.h utils.h

.PHONY: clean
clean:
	rm -f saylouis gen_public_key
	rm -f my_public_key.h
	rm -f *.o *.so
	rm -f pwdtty test.out
	rm -rf test

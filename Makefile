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

CFLAGS += -std=c99 $(WARNINGS)
LDFLAGS += -lmonocypher

.PHONY: test
test: clean
	rm -f pwdtty
	mkfifo pwdtty
	echo "test" | $(MAKE) CFLAGS='-DPWDTTY=\"pwdtty\"' saylouis decrypt
	echo "test" > pwdtty & ./saylouis < saylouis.c | ./decrypt > test.out
	rm pwdtty
	diff -q saylouis.c test.out
	rm test.out

decrypt: decrypt.o
decrypt.o: decrypt.c

saylouis: saylouis.o
saylouis.o: saylouis.c my_public_key.h

my_public_key.h: gen_public_key
	./$< > $@

gen_public_key: gen_public_key.c

.PHONY: clean
clean:
	rm -f saylouis decrypt gen_public_key
	rm -f my_public_key.h
	rm -f *.o
	rm -f pwdtty test.out

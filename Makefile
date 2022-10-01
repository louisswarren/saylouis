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

CFLAGS += -DPWDTTY=\"pwdtty\"
.PHONY: default
default: saylouis decrypt
	rm -f pwdtty
	mkfifo pwdtty
	echo "test" > tty &
	echo -n "Hello" | ./saylouis | ./decrypt
	rm pwdtty

saylouis.o: saylouis.c my_public_key.h
decrypt.o: decrypt.c

my_public_key.h: gen_public_key
	echo "test" | ./$< > $@

gen_public_key: gen_public_key.c

.PHONY: clean
clean:
	rm -f saylouis my_public_key.h gen_public_key

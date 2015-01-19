SXE_DEBUG ?= 0

CPPFLAGS  = # include paths, '.' is implicit
CFLAGS    = -O2 -DSXE_DEBUG=$(SXE_DEBUG) -g -rdynamic -fstack-protector -fno-strict-aliasing -Wall -Werror -Wextra -Wcast-align -Wcast-qual -Wformat=2 -Wformat-security -Wmissing-prototypes -Wnested-externs -Wpointer-arith -Wredundant-decls -Wshadow -Wstrict-prototypes -Wno-unknown-pragmas -Wunused -Wno-unused-result -Wwrite-strings -Wno-attributes
LDFLAGS   = # linker options (like -L for library paths)
LDLIBS    = -lm -lipq # libraries to link with

all: ipq-example

ipq-example: sxe-log.o ipq-example.o
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

debug: SXE_DEBUG = 1
debug: all

.PHONY: clean

clean:
	rm -f ipq-example *.o *.a *.t *.pass *.fail *.gcov *.gcda *.gcno

# n.o: n.c
# 	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<
# n: n.o
#	$(CC) $(LDFLAGS) n.o $(LDLIBS)

# $@ - The file name of the target of the rule
# $< - The name of the first prerequisite
# $^ - The names of all the prerequisites, with spaces between them.
# $* - The stem with which an implicit rule matches


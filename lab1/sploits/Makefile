# tools
CC := gcc
RM := rm -f

# flags
CFLAGS := -ggdb
LDFLAGS :=
LDLIBS :=

# sources
sources := sploit1.c sploit2.c sploit3.c sploit4.c sploit5.c sploit6.c
targets := $(sources:.c=)

# gmake magic
.PHONY: default all clean

#targets
default: all
all: $(targets)

clean:
	$(RM) $(targets) $(sources:.c=.o)

targets:
	cd ../targets; make

#dependencies
$(sources:.c=.o): shellcode-64.h

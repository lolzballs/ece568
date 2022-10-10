GCC=gcc
AFLCC=../afl/afl-gcc
DEBUG_CFLAGS=-g -shared -Wall -O0 -fPIC
LIBRARYCFLAGS=-fPIC -shared -Wall -O2
LIBRARY=ip_parser.a
LIBRARY_HEADER=./
DRIVER=driver
POSTLIBRARY=post_library.so

.PHONY: all clean step1 step2

all: $(DRIVER) $(POSTLIBRARY)

step1: $(DRIVER)

step2: $(POSTLIBRARY)

$(DRIVER).o: $(DRIVER).c
	$(AFLCC) -I$(LIBRARY_HEADER) $^ -c -o $@

$(DRIVER): $(DRIVER).o $(LIBRARY)
	$(AFLCC) $^ -o $@

$(POSTLIBRARY): $(POSTLIBRARY).c
	$(GCC) $(LIBRARYCFLAGS) $^ -o $@

clean:
	rm -rf *.o $(DRIVER) $(POSTLIBRARY)

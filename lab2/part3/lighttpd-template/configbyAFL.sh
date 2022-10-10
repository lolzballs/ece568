make distclean
CC=afl-clang-fast \
CFLAGS="-lpthread" \
./configure -C


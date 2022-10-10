rm -rf out-dir/*
rm -rf log/*
AFL_MAP_SIZE=256000 \
SHOW_HOOKS=1 \
AFL_DISABLE_TRIM=1 \
afl-fuzz \
    -D \
    -t 2000 \
    -m none \
    -i './input-cases/' \
    -o './out-dir' \
	-s 'rand_seed' \
    -x './dict/http_request_fuzzer.dict.txt' \
    -- lighttpd-template/src/lighttpd -D -f lighttpd-template/site_conf/test.conf -m lighttpd-template/src/.libs

for dir in lighttpd-template/src/.libs/*.so; do
        preload="$dir:$preload";
        done
modified=${preload%:}
export AFL_PRELOAD=$modified

#! /bin/bash

awk '{
    # Strip [YYYY-MM-DD HH:MM:SS.mmm] prefix (26 chars) for comparison
    msg = substr($0, 27)
    if (msg == last_msg) {
        count++
    } else {
        if (count > 1) {
            print "... repeated x" count
        }
        print
        count = 1
        last_msg = msg
    }
}
END {
    if (count > 1) {
        print "... repeated x" count
    }
}' ./steam-data/logs/uinput.log > ./steam-data/logs/uinput_summary.log

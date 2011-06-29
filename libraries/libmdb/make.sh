#!/bin/sh
warning_filter() {
    egrep -v ': In function .*:$|: warning: (ISO C99 requires rest arguments to be used|format .*%p.* has type .*struct MDB_.*\*)'
}

exit `{
    { XCFLAGS="-std=c99 -pedantic" make "$@" 2>&1; echo $? >&3; } |
    warning_filter >&2
} 3>&1`

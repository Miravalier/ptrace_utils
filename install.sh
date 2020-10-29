#!/bin/bash
ERROR='\x1B[31merror\x1B[0m'
SUCCESS='\x1B[32msuccess\x1B[0m'

cd output 2>/dev/null
if [[ $? != 0 ]]; then
    echo -e "[$ERROR] run buildall.sh before running install.sh"
    exit 1
fi

make install
if [[ $? != 0 ]]; then
    echo -e "[$ERROR] make install failed"
    exit 1
fi

echo -e "[$SUCCESS] ptrace_utils installed"
exit 0

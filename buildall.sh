#!/bin/bash

ERROR='\x1B[31merror\x1B[0m'
SUCCESS='\x1B[32msuccess\x1B[0m'
PROJECT=${PWD##*/}

mkdir output 2>/dev/null
cd output

cmake .. $@
if [[ $? != 0 ]]; then
    echo -e "[$ERROR] cmake failed"
    exit 1
fi

make
if [[ $? != 0 ]]; then
    echo -e "[$ERROR] make failed"
    exit 1
fi

echo -e "[$SUCCESS] $PROJECT built"
exit 0

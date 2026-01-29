#!/bin/sh
# Copyright 2026 atframework

SCRIPT_DIR="$( cd "$( dirname "$0" )" && pwd )";
SCRIPT_DIR="$( readlink -f $SCRIPT_DIR )";

PROJECT_DIR="$( cd "$SCRIPT_DIR/../.." && pwd )";

WORK_DIR="$PWD";

cd "$PROJECT_DIR";

cppcheck . --enable=all --xml --xml-version=2 --inconclusive --std=c11 --std=c++14 --std=posix -I "$PROJECT_DIR/third_party/atframe_utils/repo/include" -I "$PROJECT_DIR/third_party/protobuf/prebuilt/"*"/include" $@ 2>"$WORK_DIR/cppcheck.xml";

which cppcheck-htmlreport;
if [ 0 -eq $? ]; then
    mkdir -p "$WORK_DIR/cppcheck.html";
    cppcheck-htmlreport --title=libatbus.cppcheck --file="$WORK_DIR/cppcheck.xml" --report-dir="$WORK_DIR/cppcheck.html" --source-dir=. --source-encoding=utf-8 ;
fi


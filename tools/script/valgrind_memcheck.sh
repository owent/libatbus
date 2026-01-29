#!/bin/sh
# Copyright 2026 atframework

# valgrind --vgdb=full --vgdb-error=0 --leak-check=full --tool=memcheck --show-leak-kinds=all --log-file=memcheck.log --malloc-fill=0x5E "$@";
# valgrind --vgdb=yes --vgdb-error=0 --leak-check=full --tool=memcheck --show-leak-kinds=all --log-file=memcheck.log --malloc-fill=0x5E "$@";
# then, run: gdb [executable-file] --eval-command="target remote | vgdb"
valgrind --vgdb=yes --leak-check=full --tool=memcheck --show-leak-kinds=all --log-file=memcheck.log "$@";
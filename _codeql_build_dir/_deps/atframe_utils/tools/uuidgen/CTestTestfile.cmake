# CMake generated Testfile for 
# Source directory: /home/runner/work/libatbus/libatbus/atframework/atframe_utils/tools/uuidgen
# Build directory: /home/runner/work/libatbus/libatbus/_codeql_build_dir/_deps/atframe_utils/tools/uuidgen
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test([=[test-uuidgen]=] "/home/runner/work/libatbus/libatbus/_codeql_build_dir/bin/uuidgen")
set_tests_properties([=[test-uuidgen]=] PROPERTIES  LABELS "atframe_utils;atframe_utils.tools" _BACKTRACE_TRIPLES "/home/runner/work/libatbus/libatbus/atframework/atframe_utils/tools/uuidgen/CMakeLists.txt;22;add_test;/home/runner/work/libatbus/libatbus/atframework/atframe_utils/tools/uuidgen/CMakeLists.txt;0;")
add_test([=[test-uuidgen-r]=] "/home/runner/work/libatbus/libatbus/_codeql_build_dir/bin/uuidgen" "-r")
set_tests_properties([=[test-uuidgen-r]=] PROPERTIES  LABELS "atframe_utils;atframe_utils.tools" _BACKTRACE_TRIPLES "/home/runner/work/libatbus/libatbus/atframework/atframe_utils/tools/uuidgen/CMakeLists.txt;23;add_test;/home/runner/work/libatbus/libatbus/atframework/atframe_utils/tools/uuidgen/CMakeLists.txt;0;")
add_test([=[test-uuidgen-t]=] "/home/runner/work/libatbus/libatbus/_codeql_build_dir/bin/uuidgen" "-t")
set_tests_properties([=[test-uuidgen-t]=] PROPERTIES  LABELS "atframe_utils;atframe_utils.tools" _BACKTRACE_TRIPLES "/home/runner/work/libatbus/libatbus/atframework/atframe_utils/tools/uuidgen/CMakeLists.txt;24;add_test;/home/runner/work/libatbus/libatbus/atframework/atframe_utils/tools/uuidgen/CMakeLists.txt;0;")
add_test([=[test-uuidgen-V]=] "/home/runner/work/libatbus/libatbus/_codeql_build_dir/bin/uuidgen" "-V")
set_tests_properties([=[test-uuidgen-V]=] PROPERTIES  LABELS "atframe_utils;atframe_utils.tools" _BACKTRACE_TRIPLES "/home/runner/work/libatbus/libatbus/atframework/atframe_utils/tools/uuidgen/CMakeLists.txt;25;add_test;/home/runner/work/libatbus/libatbus/atframework/atframe_utils/tools/uuidgen/CMakeLists.txt;0;")
add_test([=[test-uuidgen-h]=] "/home/runner/work/libatbus/libatbus/_codeql_build_dir/bin/uuidgen" "-h")
set_tests_properties([=[test-uuidgen-h]=] PROPERTIES  LABELS "atframe_utils;atframe_utils.tools" _BACKTRACE_TRIPLES "/home/runner/work/libatbus/libatbus/atframework/atframe_utils/tools/uuidgen/CMakeLists.txt;26;add_test;/home/runner/work/libatbus/libatbus/atframework/atframe_utils/tools/uuidgen/CMakeLists.txt;0;")
add_test([=[test-uuidgen--bad-params]=] "/home/runner/work/libatbus/libatbus/_codeql_build_dir/bin/uuidgen" "--bad-params")
set_tests_properties([=[test-uuidgen--bad-params]=] PROPERTIES  LABELS "atframe_utils;atframe_utils.tools" _BACKTRACE_TRIPLES "/home/runner/work/libatbus/libatbus/atframework/atframe_utils/tools/uuidgen/CMakeLists.txt;27;add_test;/home/runner/work/libatbus/libatbus/atframework/atframe_utils/tools/uuidgen/CMakeLists.txt;0;")

file(REMOVE_RECURSE
  "_generated/include/libatbus_protocol.pb.h"
  "_generated/libatbus_protocol.pb"
  "_generated/src/libatbus_protocol.pb.cc"
)

# Per-language clean rules from dependency scanning.
foreach(lang )
  include(CMakeFiles/atbus-generate-protocol.dir/cmake_clean_${lang}.cmake OPTIONAL)
endforeach()

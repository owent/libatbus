/**
 * libatbus.h
 *
 *  Created on: 2014年8月11日
 *      Author: owent
 */

#pragma once

#ifndef LIBATBUS_PROTOCOL_H
#define LIBATBUS_PROTOCOL_H

#pragma once

#include <config/compiler/protobuf_prefix.h>

#include <google/protobuf/arena.h>

#include "libatbus_protocol.pb.h"

#include <config/compiler/protobuf_suffix.h>

namespace atbus {
    typedef ::atbus::protocol::msg msg_t;
} // namespace atbus

#define ATBUS_MACRO_RESERVED_SIZE 1024


#ifndef ATBUS_MACRO_PROTOBUF_NAMESPACE_ID
#define ATBUS_MACRO_PROTOBUF_NAMESPACE_ID google::protobuf
#endif


#endif /* LIBATBUS_PROTOCOL_H */

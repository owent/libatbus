/**
 * libatbus_channel_export.h
 *
 *  Created on: 2014年8月13日
 *      Author: owent
 */

#pragma once

#ifndef LIBATBUS_CHANNEL_EXPORT_H
#  define LIBATBUS_CHANNEL_EXPORT_H

#  pragma once

#  include <gsl/select-gsl.h>

#  include <stdint.h>
#  include <cstddef>
#  include <ostream>
#  include <string>
#  include <utility>

#  include "detail/libatbus_config.h"

#  include "detail/libatbus_adapter_libuv.h"

#  include "detail/libatbus_channel_types.h"

ATBUS_MACRO_NAMESPACE_BEGIN
namespace channel {
// utility functions
ATBUS_MACRO_API bool make_address(gsl::string_view in, channel_address_t &addr);
ATBUS_MACRO_API void make_address(gsl::string_view scheme, gsl::string_view host, int port, channel_address_t &addr);

/**
 * @brief If it's a duplex address, means both enpoint has a connection to receive and send data
 * @param in address , start with unix:/pipe:/ipv4:/ipv6:/dns:/shm: and etc.
 * @return true if it's a duplex address
 */
ATBUS_MACRO_API bool is_duplex_address(gsl::string_view in);

/**
 * @brief If it's a simplex address, means the other node has no connection and can only receive data
 * @param in address , start with unix:/pipe:/ipv4:/ipv6:/dns:/shm: and etc.
 * @return true if it's a simplex address
 */
ATBUS_MACRO_API bool is_simplex_address(gsl::string_view in);

/**
 * @brief If it's a address that can only be connected by nodes on the same machine
 * @param in address , start with unix:/pipe:/ipv4:/ipv6:/dns:/shm: and etc.
 * @return true if it's a address that can only be connected by nodes on the same machine
 */
ATBUS_MACRO_API bool is_local_host_address(gsl::string_view in);

/**
 * @brief If it's a address that can only be connected by nodes on the same process
 * @param in address , start with unix:/pipe:/ipv4:/ipv6:/dns:/shm: and etc.
 * @return true it's a address that can only be connected by nodes on the same process
 */
ATBUS_MACRO_API bool is_local_process_address(gsl::string_view in);

// memory channel
ATBUS_MACRO_API int mem_configure_set_write_timeout(mem_channel *channel, uint64_t ms);
ATBUS_MACRO_API uint64_t mem_configure_get_write_timeout(mem_channel *channel);
ATBUS_MACRO_API int mem_configure_set_write_retry_times(mem_channel *channel, size_t times);
ATBUS_MACRO_API size_t mem_configure_get_write_retry_times(mem_channel *channel);
ATBUS_MACRO_API uint16_t mem_info_get_version(mem_channel *channel);
ATBUS_MACRO_API uint16_t mem_info_get_align_size(mem_channel *channel);
ATBUS_MACRO_API uint16_t mem_info_get_host_size(mem_channel *channel);

ATBUS_MACRO_API int mem_attach(void *buf, size_t len, mem_channel **channel, const mem_conf *conf);
ATBUS_MACRO_API int mem_init(void *buf, size_t len, mem_channel **channel, const mem_conf *conf);
ATBUS_MACRO_API int mem_send(mem_channel *channel, const void *buf, size_t len);
ATBUS_MACRO_API int mem_recv(mem_channel *channel, void *buf, size_t len, size_t *recv_size);
ATBUS_MACRO_API std::pair<size_t, size_t> mem_last_action();
ATBUS_MACRO_API void mem_show_channel(mem_channel *channel, std::ostream &out, bool need_node_status,
                                      size_t need_node_data);

ATBUS_MACRO_API void mem_stats_get_error(mem_channel *channel, mem_stats_block_error &out);

#  ifdef ATBUS_CHANNEL_SHM
// shared memory channel
ATBUS_MACRO_API int shm_configure_set_write_timeout(shm_channel *channel, uint64_t ms);
ATBUS_MACRO_API uint64_t shm_configure_get_write_timeout(shm_channel *channel);
ATBUS_MACRO_API int shm_configure_set_write_retry_times(shm_channel *channel, size_t times);
ATBUS_MACRO_API size_t shm_configure_get_write_retry_times(shm_channel *channel);
ATBUS_MACRO_API uint16_t shm_info_get_version(shm_channel *channel);
ATBUS_MACRO_API uint16_t shm_info_get_align_size(shm_channel *channel);
ATBUS_MACRO_API uint16_t shm_info_get_host_size(shm_channel *channel);

/**
 * @brief shm_attach/shm_init/shm_close with shm_path
 * @param shm_path shm_path can be a number(means shared memory key) or a path begin with '/'
 * @note shm_path can only contains one '/' and the length shoud not extend 255 according to POSIX
 *       On Windows, we will add prefix of "Global\\" for shm_path, so the length of shm_path can
 *         not be grater than 248
 * @see http://man7.org/linux/man-pages/man3/shm_open.3.html
 * @see https://linux.die.net/man/3/shm_open
 * @see https://man.openbsd.org/shm_open.3
 */
ATBUS_MACRO_API int shm_attach(const char *shm_path, size_t len, shm_channel **channel, const shm_conf *conf);
ATBUS_MACRO_API int shm_init(const char *shm_path, size_t len, shm_channel **channel, const shm_conf *conf);
ATBUS_MACRO_API int shm_close(const char *shm_path);
ATBUS_MACRO_API int shm_send(shm_channel *channel, const void *buf, size_t len);
ATBUS_MACRO_API int shm_recv(shm_channel *channel, void *buf, size_t len, size_t *recv_size);
ATBUS_MACRO_API std::pair<size_t, size_t> shm_last_action();
ATBUS_MACRO_API void shm_show_channel(shm_channel *channel, std::ostream &out, bool need_node_status,
                                      size_t need_node_data);

ATBUS_MACRO_API void shm_stats_get_error(shm_channel *channel, shm_stats_block_error &out);
#  endif

// stream channel(tcp,pipe(unix socket) and etc. udp is not a stream)
ATBUS_MACRO_API void io_stream_init_configure(io_stream_conf *conf);

ATBUS_MACRO_API int io_stream_init(io_stream_channel *channel, adapter::loop_t *ev_loop, const io_stream_conf *conf);

// it will block and wait for all connections are disconnected success.
ATBUS_MACRO_API int io_stream_close(io_stream_channel *channel);

ATBUS_MACRO_API int io_stream_run(io_stream_channel *channel,
                                  adapter::run_mode_t mode = adapter::run_mode_t::RUN_NOWAIT);

ATBUS_MACRO_API int io_stream_listen(io_stream_channel *channel, const channel_address_t &addr,
                                     io_stream_callback_t callback, void *priv_data, size_t priv_size);

ATBUS_MACRO_API int io_stream_connect(io_stream_channel *channel, const channel_address_t &addr,
                                      io_stream_callback_t callback, void *priv_data, size_t priv_size);

ATBUS_MACRO_API int io_stream_disconnect(io_stream_channel *channel, io_stream_connection *connection,
                                         io_stream_callback_t callback);
ATBUS_MACRO_API int io_stream_disconnect_fd(io_stream_channel *channel, adapter::fd_t fd,
                                            io_stream_callback_t callback);
ATBUS_MACRO_API int io_stream_try_write(io_stream_connection *connection);
ATBUS_MACRO_API int io_stream_send(io_stream_connection *connection, const void *buf, size_t len);
ATBUS_MACRO_API size_t io_stream_get_max_unix_socket_length();

ATBUS_MACRO_API void io_stream_show_channel(io_stream_channel *channel, std::ostream &out);
}  // namespace channel
ATBUS_MACRO_NAMESPACE_END

#endif /* LIBATBUS_CHANNEL_EXPORT_H_ */

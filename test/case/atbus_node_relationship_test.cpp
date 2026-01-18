#include <cstdlib>
#include <cstring>
#include <iostream>
#include <sstream>
#include <vector>

#include "common/string_oprs.h"

#ifdef max
#  undef max
#endif

#ifdef min
#  undef min
#endif

#include <atbus_node.h>
#include <libatbus_protocol.h>

#include "frame/test_macros.h"

#if 0  // Unit Test for flatbuffers implements
CASE_TEST(atbus_node_rela, basic_test) {
    std::vector<unsigned char> packed_buffer;
    char test_buffer[] = "hello world!";

    {
        ::flatbuffers::FlatBufferBuilder fbb;

        uint64_t self_id = 0x12345678;
        uint32_t flags   = 0;
        flags |= atbus::protocol::ATBUS_FORWARD_DATA_FLAG_TYPE_REQUIRE_RSP;

        fbb.Finish(::atframework::atbus::protocol::Createmsg(fbb,
                                     ::atframework::atbus::protocol::Createmsg_head(fbb, ::atframework::atbus::protocol::ATBUS_PROTOCOL_CONST_ATBUS_PROTOCOL_VERSION,
                                                                       123, 0, 9876543210, self_id),
                                     ::atframework::atbus::protocol::msg_body_data_transform_req,
                                     ::atframework::atbus::protocol::Createforward_data(fbb, 0x123456789, 0x987654321, fbb.CreateVector(&self_id, 1),
                                                                           fbb.CreateVector(reinterpret_cast<const uint8_t *>(test_buffer), sizeof(test_buffer)),
                                                                           flags)
                                         .Union())

        );
        packed_buffer.assign(reinterpret_cast<const unsigned char *>(fbb.GetBufferPointer()),
            reinterpret_cast<const unsigned char *>(fbb.GetBufferPointer()) + fbb.GetSize());
        std::stringstream so;
        atfw::util::string::serialization(packed_buffer.data(), packed_buffer.size(), so);
        CASE_MSG_INFO() << "flatbuffers encoded(size=" << packed_buffer.size() << "): " << so.str() << std::endl;
    }

    {
        ::flatbuffers::Verifier msg_verify(reinterpret_cast<const uint8_t *>(&packed_buffer[0]), packed_buffer.size());
        CASE_EXPECT_TRUE(::atframework::atbus::protocol::VerifymsgBuffer(msg_verify));
        const ::atframework::atbus::protocol::msg* m = ::atframework::atbus::protocol::Getmsg(&packed_buffer[0]);

        CASE_EXPECT_EQ(::atframework::atbus::protocol::msg_body_data_transform_req, m->body_type());
        CASE_EXPECT_EQ(123, m->head()->type());
        CASE_EXPECT_EQ(0, m->head()->ret());
        CASE_EXPECT_EQ(9876543210, m->head()->sequence());
        CASE_EXPECT_EQ(0x12345678, m->head()->source_bus_id());

        CASE_EXPECT_EQ(0x123456789, m->body_as_data_transform_req()->from());
        CASE_EXPECT_EQ(0x987654321, m->body_as_data_transform_req()->to());
        CASE_EXPECT_EQ(0x12345678, m->body_as_data_transform_req()->router()->Get(0));
        CASE_EXPECT_EQ(
            0, UTIL_STRFUNC_STRNCMP(test_buffer, reinterpret_cast<const char *>(m->body_as_data_transform_req()->content()->data()), sizeof(test_buffer)));
    }
}
#endif

CASE_TEST(atbus_node_rela, copy_conf) {
  atbus::node::conf_t c1;
  atbus::node::conf_t c2(c1);

  atbus::node::default_conf((atbus::node::conf_t*)nullptr);
  atbus::node::default_conf((atbus::node::start_conf_t*)nullptr);
}

CASE_TEST(atbus_node_rela, child_endpoint_opr) {
  atbus::node::conf_t conf;
  atbus::node::default_conf(&conf);

  atbus::node::ptr_t node = atbus::node::create();
  node->init(0x12345678, &conf);

    atbus::endpoint::ptr_t ep = atbus::endpoint::create(node.get(), 0x12345679, node->get_pid(), node->get_hostname());
  // 插入到末尾
  CASE_EXPECT_EQ(0, node->add_endpoint(ep));
  CASE_EXPECT_EQ(1, node->get_immediate_endpoint_set().size());

  // 插入到中间
    ep = atbus::endpoint::create(node.get(), 0x12345589, node->get_pid(), node->get_hostname());
  CASE_EXPECT_EQ(0, node->add_endpoint(ep));
  CASE_EXPECT_EQ(2, node->get_immediate_endpoint_set().size());

    // 重复插入同ID不会增加数量
    size_t before_size = node->get_immediate_endpoint_set().size();
    ep = atbus::endpoint::create(node.get(), 0x12345679, node->get_pid(), node->get_hostname());
    CASE_EXPECT_EQ(0, node->add_endpoint(ep));
    CASE_EXPECT_EQ(before_size, node->get_immediate_endpoint_set().size());

    // 插入新端点
    ep = atbus::endpoint::create(node.get(), 0x12345680, node->get_pid(), node->get_hostname());
    CASE_EXPECT_EQ(0, node->add_endpoint(ep));
    CASE_EXPECT_EQ(3, node->get_immediate_endpoint_set().size());

  // 移除失败-找不到
  CASE_EXPECT_EQ(EN_ATBUS_ERR_ATNODE_NOT_FOUND, node->remove_endpoint(0x12349999));
  // 移除成功
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node->remove_endpoint(0x12345589));
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node->remove_endpoint(0x12345680));
}

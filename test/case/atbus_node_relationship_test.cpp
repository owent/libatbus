#include <cstdlib>
#include <cstring>
#include <iostream>
#include <sstream>
#include <vector>

#include "common/string_oprs.h"

#ifdef max
#undef max
#endif

#ifdef min
#undef min
#endif

#include <atbus_node.h>
#include <libatbus_protocol.h>

#include "frame/test_macros.h"

#if 0 // Unit Test for flatbuffers implements
CASE_TEST(atbus_node_rela, basic_test) {
    std::vector<unsigned char> packed_buffer;
    char test_buffer[] = "hello world!";

    {
        ::flatbuffers::FlatBufferBuilder fbb;

        uint64_t self_id = 0x12345678;
        uint32_t flags   = 0;
        flags |= atbus::protocol::ATBUS_FORWARD_DATA_FLAG_TYPE_REQUIRE_RSP;

        fbb.Finish(::atbus::protocol::Createmsg(fbb,
                                     ::atbus::protocol::Createmsg_head(fbb, ::atbus::protocol::ATBUS_PROTOCOL_CONST_ATBUS_PROTOCOL_VERSION,
                                                                       123, 0, 9876543210, self_id),
                                     ::atbus::protocol::msg_body_data_transform_req,
                                     ::atbus::protocol::Createforward_data(fbb, 0x123456789, 0x987654321, fbb.CreateVector(&self_id, 1),
                                                                           fbb.CreateVector(reinterpret_cast<const uint8_t *>(test_buffer), sizeof(test_buffer)),
                                                                           flags)
                                         .Union())

        );
        packed_buffer.assign(reinterpret_cast<const unsigned char *>(fbb.GetBufferPointer()), 
            reinterpret_cast<const unsigned char *>(fbb.GetBufferPointer()) + fbb.GetSize());
        std::stringstream so;
        util::string::serialization(packed_buffer.data(), packed_buffer.size(), so);
        CASE_MSG_INFO() << "flatbuffers encoded(size=" << packed_buffer.size() << "): " << so.str() << std::endl;
    }

    {
        ::flatbuffers::Verifier msg_verify(reinterpret_cast<const uint8_t *>(&packed_buffer[0]), packed_buffer.size());
        CASE_EXPECT_TRUE(::atbus::protocol::VerifymsgBuffer(msg_verify));
        const ::atbus::protocol::msg* m = ::atbus::protocol::Getmsg(&packed_buffer[0]);

        CASE_EXPECT_EQ(::atbus::protocol::msg_body_data_transform_req, m->body_type());
        CASE_EXPECT_EQ(123, m->head()->type());
        CASE_EXPECT_EQ(0, m->head()->ret());
        CASE_EXPECT_EQ(9876543210, m->head()->sequence());
        CASE_EXPECT_EQ(0x12345678, m->head()->src_bus_id());

        CASE_EXPECT_EQ(0x123456789, m->body_as_data_transform_req()->from());
        CASE_EXPECT_EQ(0x987654321, m->body_as_data_transform_req()->to());
        CASE_EXPECT_EQ(0x12345678, m->body_as_data_transform_req()->router()->Get(0));
        CASE_EXPECT_EQ(
            0, UTIL_STRFUNC_STRNCMP(test_buffer, reinterpret_cast<const char *>(m->body_as_data_transform_req()->content()->data()), sizeof(test_buffer)));
    }
}
#endif

CASE_TEST(atbus_node_rela, child_endpoint_opr) {
    atbus::node::conf_t conf;
    atbus::node::default_conf(&conf);
    conf.subnets.push_back(atbus::endpoint_subnet_conf(0, 16));

    atbus::node::ptr_t node = atbus::node::create();
    node->init(0x12345678, &conf);


    std::vector<atbus::endpoint_subnet_conf> ep_subnets;
    ep_subnets.push_back(atbus::endpoint_subnet_conf(0, 8));
    atbus::endpoint::ptr_t ep = atbus::endpoint::create(node.get(), 0x12345679, ep_subnets, node->get_pid(), node->get_hostname());
    // 插入到末尾
    CASE_EXPECT_EQ(0, node->add_endpoint(ep));
    CASE_EXPECT_EQ(1, node->get_routes().size());

    // 插入到中间
    ep = atbus::endpoint::create(node.get(), 0x12345589, ep_subnets, node->get_pid(), node->get_hostname());
    CASE_EXPECT_EQ(0, node->add_endpoint(ep));
    CASE_EXPECT_EQ(2, node->get_routes().size());

    // 新端点子域冲突-父子关系
    ep_subnets.clear();
    ep_subnets.push_back(atbus::endpoint_subnet_conf(0, 4));
    ep = atbus::endpoint::create(node.get(), 0x12345680, ep_subnets, node->get_pid(), node->get_hostname());
    CASE_EXPECT_EQ(EN_ATBUS_ERR_PARAMS, node->add_endpoint(atbus::endpoint::ptr_t()));
    CASE_EXPECT_EQ(EN_ATBUS_ERR_ATNODE_MASK_CONFLICT, node->add_endpoint(ep));

    // 新端点子域冲突-子父关系
    ep_subnets.clear();
    ep_subnets.push_back(atbus::endpoint_subnet_conf(0, 12));
    ep = atbus::endpoint::create(node.get(), 0x12345780, ep_subnets, node->get_pid(), node->get_hostname());
    CASE_EXPECT_EQ(EN_ATBUS_ERR_ATNODE_MASK_CONFLICT, node->add_endpoint(ep));
    ep = atbus::endpoint::create(node.get(), 0x12345480, ep_subnets, node->get_pid(), node->get_hostname());
    CASE_EXPECT_EQ(EN_ATBUS_ERR_ATNODE_MASK_CONFLICT, node->add_endpoint(ep));

    // 新端点子域冲突-ID不同子域相同
    ep_subnets.clear();
    ep_subnets.push_back(atbus::endpoint_subnet_conf(0, 8));
    ep = atbus::endpoint::create(node.get(), 0x12345680, ep_subnets, node->get_pid(), node->get_hostname());
    CASE_EXPECT_EQ(EN_ATBUS_ERR_ATNODE_MASK_CONFLICT, node->add_endpoint(ep));

    // 移除失败-找不到
    CASE_EXPECT_EQ(EN_ATBUS_ERR_ATNODE_NOT_FOUND, node->remove_endpoint(0x12345680));
    // 移除成功
    CASE_EXPECT_EQ(EN_ATBUS_ERR_SUCCESS, node->remove_endpoint(0x12345589));
}

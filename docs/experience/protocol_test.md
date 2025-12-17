数据
------------

```js
{
    "head": {
        "cmd": 1, // 这个字段msgpack独占
        "version": 2,
        "type": 123,
        "ret": 0,
        "sequence": 9876543210,
        "source_bus_id": 0x12345678
    },
    "bdoy": {
        "data_transform_req": {
            "from": 0x123456789,
            "to": 0x987654321,
            "router": [0x123456789],
            "content": "hello world!\0",
            "flag": 1
        }
    }
}
```

flatbuffers
------------

```flatbuffers
table forward_data {
    from    : uint64   (id: 0);
    to      : uint64   (id: 1);
    router  : [uint64] (id: 2);
    content : [ubyte]  (id: 3);
    flags   : uint32   (id: 4);
}

union message_body {
    // invalid_body        : string              (id: 0);
    custom_command_req  : custom_command_data = 1,
    custom_command_rsp  : custom_command_data = 2,
    data_transform_req  : forward_data        = 3,
    data_transform_rsp  : forward_data        = 4,
    // ...
}

table message_head {
    version     : int32     (id: 0);
    type        : int32     (id: 1);
    ret         : int32     (id: 2);
    sequence    : uint64    (id: 3);
    source_bus_id  : uint64    (id: 4);
}

table msg {
    head: message_head  (id: 0);
    body: message_body  (id: 2); // id: 1 is implicitly added for body case by flatc
}
```

```cpp
std::vector<unsigned char> packed_buffer;
char test_buffer[] = "hello world!";

{
    ::flatbuffers::FlatBufferBuilder fbb;

    uint64_t self_id = 0x12345678;
    uint32_t flags   = 0;
    flags |= atbus::protocol::ATBUS_FORWARD_DATA_FLAG_TYPE_REQUIRE_RSP;

    fbb.Finish(::atframework::atbus::protocol::Createmsg(fbb,
                                    ::atframework::atbus::protocol::Createmessage_head(fbb, ::atframework::atbus::protocol::ATBUS_PROTOCOL_CONST_ATBUS_PROTOCOL_VERSION,
                                                                    123, 0, 9876543210, self_id),
                                    ::atframework::atbus::protocol::message_body_data_transform_req,
                                    ::atframework::atbus::protocol::Createforward_data(fbb, 0x123456789, 0x987654321, fbb.CreateVector(&self_id, 1),
                                                                        fbb.CreateVector(reinterpret_cast<const uint8_t *>(test_buffer), sizeof(test_buffer)),
                                                                        flags)
                                        .Union())

    );
    packed_buffer.assign(reinterpret_cast<const unsigned char *>(fbb.GetBufferPointer()), 
        reinterpret_cast<const unsigned char *>(fbb.GetBufferPointer()) + fbb.GetSize());
    std::stringstream so;
    atfw::util::string::serialization(packed_buffer.data(), packed_buffer.size(), so);
    std::cout<< "flatbuffers encoded(size=" << packed_buffer.size() << "): " << so.str() << std::endl;
}
```

```
flatbuffers encoded(size=160): \020\000\000\000\000\000\012\000\022\000\010\000\007\000\014\000\012\000\000\000\000\000\000\003l\000\000\000\024\000\000\000\000\000\016\000 \000\020\000\030\000\004\000\010\000\014\000\016\000\000\0000\000\000\000\030\000\000\000\002\000\000\000\611gE#\001\000\000\000!Ce\607\011\000\000\000\015\000\000\000hello world!\000\000\000\000\001\000\000\000xV4\022\000\000\000\000\000\000\000\000\000\000\016\000\034\000\004\000\010\000\000\000\014\000\024\000\016\000\000\000\002\000\000\000{\000\000\000\752\026\660L\002\000\000\000xV4\022\000\000\000\000
```

message pack
------------

```cpp
enum ATBUS_PROTOCOL_CMD {
    ATBUS_CMD_INVALID = 0,

    //  数据协议
    ATBUS_CMD_DATA_TRANSFORM_REQ = 1,
    ATBUS_CMD_DATA_TRANSFORM_RSP,

    // ...

    ATBUS_CMD_MAX
};
struct bin_data_block {
    const void *ptr;
    size_t size;
};

struct forward_data {
    ATBUS_MACRO_BUSID_TYPE from;                // ID: 0
    ATBUS_MACRO_BUSID_TYPE to;                  // ID: 1
    std::vector<ATBUS_MACRO_BUSID_TYPE> router; // ID: 2
    bin_data_block content;                     // ID: 3
    int flags;                                  // ID: 4

    forward_data() : from(0), to(0), flags(0) {
        content.size = 0;
        content.ptr  = nullptr;
    }
    MSGPACK_DEFINE(from, to, router, content, flags);
};

class message_body {
public:
    forward_data *forward;
    // ...

    message_body() : forward(nullptr) {}
    ~message_body() {
        if (nullptr != forward) {
            delete forward;
        }
        // ... 
    }
};

struct message_head {
    ATBUS_PROTOCOL_CMD cmd;            // ID: 0
    int32_t version;                   // ID  1
    int32_t type;                      // ID: 2
    int32_t ret;                       // ID: 3
    uint64_t sequence;                 // ID: 4
    uint64_t source_bus_id;               // ID: 5


    message_head() : cmd(ATBUS_CMD_INVALID), version(2), type(0), ret(0), sequence(0) {}

    MSGPACK_DEFINE(cmd, type, ret, sequence, source_bus_id, version);
};

struct msg {
    message_head head; // map.key = 1
    message_body body; // map.key = 2
};

// 下面对自定义encode/decode的封装就不贴了
```

```cpp
atbus::protocol::msg m_src;
std::string packed_buffer;
char test_buffer[] = "hello world!";

{
    m_src.head.cmd        = ATBUS_CMD_DATA_TRANSFORM_REQ;
    m_src.head.version    = 2;
    m_src.head.type       = 123;
    m_src.head.ret        = 0;
    m_src.head.sequence   = 9876543210;
    m_src.head.source_bus_id = 0x12345678;

    m_src.body.forward = new ::atframework::atbus::protocol::forward_data();
    m_src.body.forward->from = 0x12345678;
    m_src.body.forward->to = 0x987654321;
    m_src.body.forward->content.ptr = test_buffer;
    m_src.body.forward->content.size = sizeof(test_buffer);
    m_src.body.forward->router.push_back(0x12345678);
    m_src.body.forward->flags = 1;

    std::stringstream ss;
    msgpack::pack(ss, m_src);
    packed_buffer = ss.str();
    std::stringstream so;
    atfw::util::string::serialization(packed_buffer.data(), packed_buffer.size(), so);
    std::cout<< "msgpack encoded(size=" << packed_buffer.size() << "): " << so.str() << std::endl;
}
```

```
msgpack encoded(size=59): \602\001\626\001{\000\717\000\000\000\002L\660\026\752\716\0224Vx\002\002\625\716\0224Vx\717\000\000\000\011\607eC!\621\716\0224Vx\704\015hello world!\000\001
```

protobuf
------------

```protobuf
syntax = "proto3";

package atbus.protocol;

option optimize_for = SPEED;
option cc_enable_arenas = true;

enum ATBUS_PROTOCOL_CONST {
    option allow_alias             = true;
    ATBUS_PROTOCOL_CONST_UNKNOWN   = 0;
    ATBUS_PROTOCOL_VERSION         = 2;
    ATBUS_PROTOCOL_MINIMAL_VERSION = 2; // minimal protocol version supported
}

enum ATBUS_FORWARD_DATA_FLAG_TYPE {
    FORWARD_DATA_FLAG_NONE = 0;
    // all flags must be power of 2
    FORWARD_DATA_FLAG_REQUIRE_RSP = 1;
}

message forward_data {
    uint64   from           = 1;
    uint64   to             = 2;
    repeated uint64 router  = 3;
    bytes           content = 4;
    uint32          flags   = 5;
}

message message_head {
    int32  version    = 1;
    int32  type       = 2;
    int32  ret        = 3;
    uint64 sequence   = 4;
    uint64 source_bus_id = 5;
}

message msg {
    message_head head = 1;
    oneof    message_body {
        // ... 
        forward_data        data_transform_req = 13;
        // ...
    }
}
```

```cpp
::google::protobuf::Arena arena;
#if defined(PROTOBUF_VERSION) && PROTOBUF_VERSION >= 5027000
atbus::protocol::msg *    m_src = ::google::protobuf::Arena::Create<atbus::protocol::msg>(&arena);
#else
atbus::protocol::msg *    m_src = ::google::protobuf::Arena::CreateMessage<atbus::protocol::msg>(&arena);
#endif
std::string               packed_buffer;
char                      test_buffer[] = "hello world!";

{
    m_src->mutable_head()->set_version(2);
    m_src->mutable_head()->set_type(123);
    m_src->mutable_head()->set_ret(0);
    m_src->mutable_head()->set_sequence(9876543210);
    m_src->mutable_head()->set_source_bus_id(0x12345678);

    m_src->mutable_data_transform_req()->set_from(0x12345678);
    m_src->mutable_data_transform_req()->set_to(0x987654321);
    m_src->mutable_data_transform_req()->set_content(test_buffer, sizeof(test_buffer));
    m_src->mutable_data_transform_req()->add_router(0x12345678);
    m_src->mutable_data_transform_req()->set_flags(atbus::protocol::FORWARD_DATA_FLAG_REQUIRE_RSP);

    m_src->SerializeToString(&packed_buffer);
    std::stringstream so;
    atfw::util::string::serialization(packed_buffer.data(), packed_buffer.size(), so);
    std::cout << "arena(allocated= " << arena.SpaceAllocated() << ", used= " << arena.SpaceUsed() << "), protobuf encoded(size=" << packed_buffer.size()
              << "): " << so.str() << std::endl;
}
```

```
arena(allocated= 768, used= 376), protobuf encoded(size=57): \012\020\010\002\020{ \752\655\700\745$(\770\654\721\621\001j%\010\770\654\721\621\001\020\641\606\625\673\630\001\032\005\770\654\721\621\001"\015hello world!\000(\001
```

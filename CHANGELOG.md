CHANGELOG
============

1.2.0
------------

这是一个比较大规模的重构，并且协议层向前不兼容，API除协议数据读取外基本兼容

1. 移除对msgpack的依赖，使用flatbuffers作为内部交互协议
2. 增加access_token的支持，防止误操作
3. 增加children_prefix功能，可以支持自身node的id不在自己管理的子节点集合中
4. 重构父节点范围管理的结构，现在更清晰易懂一些
5. 增加（共享）内存通道的版本号功能，增加协议版本号功能，用于跨版本兼容性检查
6. 连接层面也增加错误计数，如果超出容忍值直接断开连接
7. 支持字符串路径的共享内存（使用: ```shm_open/ftruncate/mmap/munmap/shm_unlink/close/fstat``` 来管理），支持字符串命名的共享内存（长度限定为NAME_MAX(255）)

### TODO 1.2.0

- [ ] children_prefix功能
- [ ] 单元测试: 父节点连接注册信息的子网范围不包含本节点或本节点的子网，出错
- [ ] 单元测试: 父子节点在不同的子网范围
- [ ] 单元测试: 转发目标和来源ep一样，回环，出错
- [ ] 单元测试: endpoint::merge_subnets
- [ ] 单元测试: endpoint_subnet_range::contain
- [ ] 单元测试: endpoint_subnet_range::search_subnet_for_id(====#^++####====)
- [x] access_token验证的单元测试（成功+失败）
- [ ] 重构父节点范围管理的结构
- [x] 协议版本兼容性单元测试
- [x] 内存通道版本兼容性单元测试
- [x] 字符串路径共享内存测试
- [x] 握手connection的backlog支持，定时器优化
- [x] unit test -- max msg size : EN_ATBUS_ERR_INVALID_SIZE
- [x] msg size -> configure: 256KB

1.1.0
------------

...
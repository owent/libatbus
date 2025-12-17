#include <cstdlib>
#include <cstring>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <string>

#include <atbus_node.h>
#include <libatbus_protocol.h>

int main() {
#if defined(UTIL_CONFIG_COMPILER_CXX_LAMBDAS) && UTIL_CONFIG_COMPILER_CXX_LAMBDAS
  // 初始化默认配置
  atbus::node::conf_t conf;
  atbus::node::default_conf(&conf);

  // 子域的范围设为16（后16位都是子节点）, id_prefix=0 等于使用endpoint自己的ID
  conf.subnets.push_back(atbus::endpoint_subnet_conf(0, 16));

  // 初始化libuv事件分发器
  uv_loop_t ev_loop;
  uv_loop_init(&ev_loop);

  // 指定事件分发器
  conf.ev_loop = &ev_loop;

  {
    // 创建两个通信节点
    atbus::node::ptr_t node1 = atbus::node::create();
    atbus::node::ptr_t node2 = atbus::node::create();

    // 初始化
    node1->init(0x12345678, &conf);  // BUS ID=0x12345678, 0x1234XXXX 都是子节点
    node2->init(0x12356789, &conf);  // BUS ID=0x12356789, 0x1235XXXX 都是子节点
    // 所以这两个都是兄弟节点

    // 各自监听地址
    node1->listen("ipv4://127.0.0.1:16387");
    node2->listen("ipv4://127.0.0.1:16388");

    // 启动初始化
    node1->start();
    node2->start();

    // 启动连接
    node1->connect("ipv4://127.0.0.1:16388");

    // 等待连接成功
    // 如果是拥有共同父节点的兄弟节点不能这么判定，因为在第一次发消息前是不会建立连接的
    for (int i = 0; i < 512; ++i) {
      if (node2->is_endpoint_available(node1->get_id()) && node1->is_endpoint_available(node2->get_id())) {
        break;
      }

      uv_run(conf.ev_loop, UV_RUN_ONCE);

      // 定期执行proc函数，用于处理内部定时器
      // 第一个参数是Unix时间戳（秒），第二个参数是微秒
      node1->proc(time(nullptr), 0);
      node2->proc(time(nullptr), 0);
    }

    // 设置接收到消息后的回调函数
    bool recved = false;
    node2->set_on_recv_handle([&recved](const atbus::node &n, const atbus::endpoint *ep, const atbus::connection *conn,
                                        const atbus::message &, const void *buffer, size_t len) {
      if (nullptr != ep && nullptr != conn) {
        std::cout << "atbus node 0x" << std::ios::hex << n.get_id() << " receive data from 0x" << std::ios::hex
                  << ep->get_id() << "(connection: " << conn->get_address().address << "): ";
      }
      std::cout.write(reinterpret_cast<const char *>(buffer), static_cast<std::streamsize>(len));
      std::cout << std::endl;
      recved = true;
      return 0;
    });

    // 发送数据
    std::string send_data = "hello world!";
    node1->send_data(node2->get_id(), 0, send_data.data(), send_data.size());

    // 等待发送完成
    while (!recved) {
      uv_run(conf.ev_loop, UV_RUN_ONCE);

      // 定期执行proc函数，用于处理内部定时器
      // 第一个参数是Unix时间戳（秒），第二个参数是微秒
      node1->proc(time(nullptr), 0);
      node2->proc(time(nullptr), 0);
    }

    // 析构时会自动关闭所持有的资源
  }

  // 关闭libuv事件分发器
  while (UV_EBUSY == uv_loop_close(&ev_loop)) {
    uv_run(&ev_loop, UV_RUN_ONCE);
  }
#else
  std::cout << "lambda not supported, ignore this sample" << std::endl;
#endif
  return 0;
}

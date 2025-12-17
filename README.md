# libatbus

用于搭建高性能、全异步(a)、树形结构(t)的BUS消息系统的跨平台框架库

[![ci-badge]][ci-link] [![codecov badge]][codecov status]

[ci-badge]: https://github.com/atframework/libatbus/actions/workflows/main.yml/badge.svg "Github action build status"
[ci-link]:  https://github.com/atframework/libatbus/actions/workflows/main.yml "Github action build status"
[codecov badge]: https://codecov.io/gh/atframework/libatbus/branch/main/graph/badge.svg
[codecov status]: https://codecov.io/gh/atframework/libatbus

## CI Job Matrix

| Target System | Toolchain          | Note                  |
| ------------- | ------------------ | --------------------- |
| Linux         | GCC                |
| Linux         | Clang              | With libc++           |
| MinGW64       | GCC                | Dynamic linking       |
| Windows       | Visual Studio 2022 | Static linking        |
| Windows       | Visual Studio 2022 | Dynamic linking       |
| macOS         | AppleClang         | With libc++           |

## 依赖

+ 支持c++17的编译器
  > + GCC: 7.1 及以上
  > + Clang: 7 及以上
  > + VC: VS2022 及以上

+ [cmake](https://cmake.org/download/) 3.24.0 以上

## 设计初衷和要点

1. **[扩展性]** 根据很多业务的需要，预留足够长的ID段（64位），用以给不同的ID段做不同类型的业务区分。
  > 现有很多框架都是32位（比如腾讯的tbus和云风的[skynet](https://github.com/cloudwu/skynet)），在服务类型比较多的时候必须小心设计服务ID,以免冲突。
  >
  > 当然也有考虑到以后可能会扩展为带Hash的字符串，所以在编译选项上做了预留。但是目前还是uint64_t

2. **[高性能]** 同物理机之间可以直接使用共享内存通信，大幅提高消息分发的性能。跨物理机之间会使用tcp通信。并且这个通信方式的选择是完全自动并透明的（尽可能选择更快的方式发送消息），业务层完全不需要关心。
3. **[跨平台]** 拥有不同习惯的Developer可以使用自己熟悉的工具，提高开发速度
4. **[动态路由]** 父子节点间会至少保持一条连接，自动断线重连。同父的兄弟节点之间完全按需建立连接。并且这个过程都是自动完成的，不需要提前初始化。
  > 同样，新增节点和移除节点也不需要做什么特别的初始化操作。不会影响到已经在线上的服务。

5. **[低消耗]** 采用无锁队列，提高CPU性能。（共享）内存通道支持多端写入，一端读取，减少内存浪费。
  > 如果N个节点两两互联，每个节点可以只拥有一个（共享）内存通道。即总共只有N个通道，内存消耗为N*每个通道内存占用
  >
  > 一些其他的系统（比如tbus和我们目前的服务器框架）如果N个节点两两互联，每两个节点之间都要创建（共享）内存通道。即总共只有N*N个通道，内存消耗为N*N*每个通道内存占用。非常浪费

6. **[简化设计]** 根据一些实际的项目情况，把父子节点间的关系限定为Bus ID的后N位有包含关系，类似路由器的路由表的策略。
  > 比如 0x12345678 可以控制的子节点有16位（0x12345678/16），那么0x12340000-0x1234FFFF都可以注册为它的子节点。
  >
  > 如同IP协议中 192.168.1.1/24 路由表能管理 192.168.1.0-192.168.1.255 一样。当然这里的24指前24位，而前面提到的16指后16位。
  >
  > 这么简化以后很多节点关系维护和通信都能简单很多并且能提高性能。

## 环境准备和构建流程

使用cmake标准构建方式，默认的编译目标为Debug版本，详见 [使用（编译）流程](docs/Build.md)

**注意： 默认的编译选项是Debug模式，压测和正式环境请使用 cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo 源码目录 [其他选项] 编译（相当于gcc -O2 -g -ggdb -DNDEBUG -Wall -Werror或MSVC /O2）**

**注意： Windows下私有共享内存不允许跨进程共享，公有共享内存必须有管理员权限。如果Windows下出现初始化共享内存错误请使用管理员权限运行。**

## 使用示例

简要的使用示例见 [使用示例](docs/Usage.md)

更加详细的请参考单元测试和[tools](tools)目录内的代码

## Benchmark

压力测试和对比见[docs/Benchmark.md](docs/Benchmark.md)

## 支持工具

Linux下 GCC编译安装脚本(支持离线编译安装):

1. [GCC](https://github.com/owent-utils/bash-shell/tree/master/GCC%20Installer)
2. [LLVM & Clang](https://github.com/owent-utils/bash-shell/tree/master/LLVM%26Clang%20Installer)

## LICENSE

+ libatbus 采用[MIT License](LICENSE)
+ Flatbuffers 采用[Apache License, Version 2.0](LICENSE-Apache.txt)
+ libuv 采用[Node's license协议](NODE_S_LICENSE)（类似MIT License）

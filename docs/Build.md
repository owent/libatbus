使用（编译）流程
======

依赖工具集合库
------

+ 支持c++0x或c++11的编译器(为了代码尽量简洁,特别是少做无意义的平台兼容，依赖部分 C11和C++11的功能，所以不支持过低版本的编译器)

> + GCC: 4.7 及以上（建议gcc 4.8及以上）
> + Clang: 3.0 及以上 （建议 clang 3.4及以上）
> + VC: 10 及以上 （建议VC 12及以上）

+ [cmake](https://cmake.org/download/) 3.13.0 以上
+ [protobuf](https://github.com/protocolbuffers/protobuf)

> 用于协议打解包,仅使用头文件

+ [libuv](http://libuv.org/)（用于网络通道）

> 用于协议打解包,仅使用头文件
>
> 手动编译libuv则需要额外的软件集，基本有: gcc/clang/msvc, autoconf, automake, make, pthread, m4

+ [atframe_utils](https://github.com/atframework/atframe_utils)（基础公共代码，检测到不存在会自动下载）
+ (可选)[python](http://python.org/) （周边工具集）
+ (可选)tar, curl, wget: 如果使用内置的脚本自动构建依赖的库，则这些是必要的工具

环境准备(开发环境最小依赖)
------
### Windows + MSVC
1. [cmake](https://cmake.org/download/)
2. [visual studio](https://www.visualstudio.com)
3. [libuv](http://dist.libuv.org/dist)
4. 执行 mkdir build && cd build && cmake .. -G "Visual Studio 15 2017 Win64" -DLIBUV_ROOT=[libuv安装目录] -DFlatbuffers_ROOT=[flatbuffers的安装目录]
5. 编译打开Visual Studio编译或 cmake --build . --config RelWithDebInfo

详情可参考 [Appceyor CI](../appveyor.yml) 脚本

或者也可以选择使用nmake编译。

**生成目标(-G 选项的值)请按自己所在环境手动修改，否则会使用默认的配置，MSVC的默认会生成x86版本的工程文件**

上面最后一条命令可以根据实际环境修改参数，这里只提供一个示例

### Windows + MinGW(msys2)
1. 安装[Msys2](http://msys2.github.io/)
2. Msys2里安装依赖组件
> ```
> for pkg_name in git m4 curl wget tar autoconf automake mingw-w64-i686-toolchain mingw-w64-x86_64-toolchain mingw-w64-x86_64-libtool mingw-w64-i686-libtool python; do pacman -S --noconfirm --needed $pkg_name; done
> ```
> 具体可以根据 编译目标裁剪，这里把32位和64位依赖库都安装上了

3. MinGW shell 下执行cmake构建命令
> 注意一定是要MingGW的shell（libuv不支持msys shell），msys2默认开启的是msys shell
> 
> 通常情况下可以通过以下方式打开MingGW shell
> + C:\msys64\mingw32.exe   -- 32位
> + C:\msys64\mingw64.exe   -- 64位
> 
> 请指定生成 MSYS Makefiles 工程文件(-G "MSYS Makefiles")

其他MinGW环境请自行安装依赖库

详情可参考 [Appceyor CI](../appveyor.yml) 脚本

### Linux
1. gcc 4.4及以上
2. autoconf
3. gdb
4. valgrind
5. curl
6. wget
7. tar
8. m4
9. cmake
10. automake
11. make
12. git

以上请用Linux发行版的包管理器安装，然后正常使用cmake即可

比如CentOS:
```
yum install gcc gcc-c++ autoconf automake gdb valgrind curl wget tar m4 automake make git;
wget -c "https://cmake.org/files/v3.9/cmake-3.9.4-Linux-x86_64.sh" -O "cmake-Linux-x86_64.sh";
bash cmake-Linux-x86_64.sh --skip-license --prefix=/usr ;
```

详情可参考 [Travis CI](../.travis.yml) 脚本

### OSX

1. 安装 [brew](http://brew.sh/)
2. 安装 xcode
3. sudo brew install gcc gdb autoconf automake make curl wget tar m4 cmake git

详情可参考 [Travis CI](../.travis.yml) 脚本

编译和构建
------

### 编译选项

除了cmake标准编译选项外，libatbus还提供一些额外选项

+ CMAKE_BUILD_TYPE (默认: Debug): 构建类型，目前**默认是Debug**方式构建。生产环境建议使用**-DCMAKE_BUILD_TYPE=RelWithDebInfo**(相当于gcc -O2 -g -ggdb -DNDEBUG)
+ LIBUV_ROOT: 手动指定libuv的安装目录
+ Flatbuffers_ROOT: 手动指定flatbuffers的安装目录，需要符合cmake的find_package规则，使用flatbuffers官方提供的config文件，且必须编译lib和flatc
+ CMAKE_MSVC_RUNTIME （默认: MD）: 使用MSVC编译时默认使用MD/MDd运行时，如果需要尽可能一处依赖并使用MT请把这个值设为MT
+ PROJECT_ENABLE_SAMPLE (默认: NO): 是否编译Sample代码
+ PROJECT_ENABLE_UNITTEST (默认: NO): 是否编译单元测试代码
+ PROJECT_ENABLE_TOOLS (默认: NO): 是否编译工具集（主要是压力测试工具）
+ ============= 以上选项根据实际环境配置，以下选项不建议修改 =============
+ ATBUS_MACRO_BUSID_TYPE (默认: uint64_t): busid的类型，建议不要设置成大于64位，否则需要修改protocol目录内的busid类型，并且重新生成协议文件
+ ATBUS_MACRO_DATA_NODE_SIZE (默认: 128): atbus的内存通道node大小（必须是2的倍数）
+ ATBUS_MACRO_DATA_ALIGN_SIZE (默认: 16): atbus的内存内存块对齐大小，大多数某些架构要求对齐到16
+ ATBUS_MACRO_DATA_SMALL_SIZE (默认: 3072): 流通道小数据块大小（用于优化减少内存拷贝）
+ ATBUS_MACRO_HUGETLB_SIZE (默认: 4194304): 大页表分页大小（用于优化共享内存分页,此功能暂时关闭，所以并不生效）
+ ATBUS_MACRO_MSG_LIMIT (默认: 262144): 默认消息体大小限制
+ ATBUS_MACRO_CONNECTION_CONFIRM_TIMEOUT (默认: 30): 默认连接确认时限
+ ATBUS_MACRO_CONNECTION_BACKLOG (默认: 128): 默认握手队列的最大连接数
+ ATBUS_MACRO_SHM_MEM_CHANNEL_LENGTH (默认: 8388608): 共享内存和内存通道的默认大小
+ ATBUS_MACRO_IOS_SEND_BUFFER_LENGTH (默认: 2097152): IO流（tcp/unix sock）发送通道的默认大小
+ GTEST_ROOT: 使用GTest单元测试框架
+ BOOST_ROOT: 设置Boost库根目录
+ PROJECT_TEST_ENABLE_BOOST_UNIT_TEST: 使用Boost.Test单元测试框架(如果GTEST_ROOT和此项都不设置，则使用内置单元测试框架)


### 示例构建脚本(MinGW64)
```
git clone --depth=1 "https://github.com/atframework/libatbus.git"
mkdir libatbus/build;
cd libatbus/build;
# cmake .. -G "MSYS Makefiles" [其他可选项]
cmake .. -DCMAKE_INSTALL_PREFIX=/usr/local/libatbus;
cmake --build .;                    # 或 make
cmake --build . --target install;   # 或 make install
```

### 运行和测试

```bash
# MSVC请在构建目录下使用以下命令运行单元测试，其中Debug和之气按编译时的--config选项内容保持一致
ctest . -V -C Debug
# Unix like环境（包括mingw）在构建目录运行下面命令即可
ctest . -V
```

单元测试会生成在[构建目录]/test下，sample会生成在[构建目录]/sample下，工具程序（比如压力测试程序）会生成在[构建目录]/tools下。并且不会被install

cmake --build . --target install(或者make构建系统的make install) 仅会安装include目录和编译好的libs

**注意:** Windows下MSVC直接安装的libuv会链接dll库，但是构建脚本不会把dll拷贝到执行目录，所以直接运行可能会出错。这时候把libuv.dll手动拷贝到执行目录即可 

附加说明
------

### 目录结构说明

+ third_party: 外部组件（不一定是依赖项）
+ docs: 文档目录
+ include: 导出lib的包含文件（注意不导出的内部接口后文件会直接在src目录里）
+ project: 工程工具和配置文件集
+ protocol: 协议描述文件目录
+ sample: 使用示例目录，每一个cpp文件都是一个完全独立的例子
+ src: 源文件和内部接口申明目录
+ test: 测试框架及测试用例目录

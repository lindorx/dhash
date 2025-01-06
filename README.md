# dhash
按照公开算法实现的哈希库，支持ascon-hash、sha224、sha256、sha384、sha512、sm3  

头文件路径：/usr/include/dhash/  
链接库路径：/usr/lib/x86_64-linux-gnu/  

# 使用方法
## 1. 获取代码

到对应页面下载代码或者像下面一样克隆仓库

```c
git clone https://github.com/lindorx/dhash.git
```
或
```c
git clone https://gitee.com/lindorx/dhash.git
```

## 2. 编译安装

cd进入目录，执行如下代码
```
# 编译
make build
# 安装
make install
# 编译测试文件
make test
```
如果编译成功，“ make test ”之后将生成 test/test.out 文件，执行
```
./test/test.out
```
输出如下结果表示编译成功
```
EA09AE9CC6768C50FCEE903ED054556E5BFC8347907F12598AA24193
2CF24DBA5FB0A30E26E83B2AC5B9E29E1B161E5C1FA7425E73043362938B9824
59E1748777448C69DE6B800D7A33BBFB9FF1B463E44354C3553BCDB9C666FA90125A3C79F90397BDF5F6A13DE828684F
9B71D224BD62F3785D96D46AD3EA3D73319BFBC2890CAADAE2DFF72519673CA72323C3D99BA5C11D7C7ACC6E14B8C5DA0C4663475C2E5C3ADEF46F73BCDEC043
BECBBFAAE6548B8BF0CFCAD5A27183CD1BE6093B1CCECCC303D9C61D0A645268
B3EAC9A88301565C30B3D802FF7F0000A02AE13BF77F000030B3D802FF7F0000
```

## 3. make命令说明

执行“ make [命令] ”以对源代码进行操作

| 命令 | 说明 |
| ---- | ---- |
| build | 将源代码编译为libdhash.so文件，同时生成dhash-install目录，作为临时根目录存储需要安装的文件 |
| install | 此操作会将dhash-install目录下的文件按照路径复制到系统对应的目录 |
| uninstall | 删去install向系统目录安装的文件 |
| test | 生成测试文件，路径：test/test.out |
| | |


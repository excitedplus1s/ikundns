# ikundns
某大型 DPI RST阻断保护PoC，在中国境内保护通过TCP进行的 DNS查询 不被 RST，仅供研究用途
仅支持 A 记录查询

# 编译

gcc ikundns.c -lpthread ikundns

# 使用示例
./ikundns wikipedia.org

# 警告
阅读此代码，可能会对您的健康造成损害。此代码故意在命名方式上进行了一定的“捣乱”，编写成这个样是故意的。

另外某些恶意响应的DNS信息可能会导致 RCE


# 合法性说明
《国际联网暂行规定》第六条规定：“计算机信息网络直接进行国际联网，必须使用邮电部国家公用电信网提供的国际出入口信道。任何单位和个人不得自行建立或者使用其他信道进行国际联网。”
ikundns 使用的都是“公用电信网提供的国际出入口信道”，从国外DNS服务器到国内用户电脑上ikundns 程序的流量，使用的是正常流量通道，其间未对流量进行任何额外加密，ikundns 获取到DNS查询数据之后的整个过程完全在国内，不再适用国际互联网相关之规定。

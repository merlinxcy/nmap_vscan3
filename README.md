# nmap_vscan3
nmap service and application version detection使用nmap的指纹库进行版本识别，可以方便的规避特征

nixawk/namp_vscan3的项目已经停止维护了，该项目在其基础上进行迭代。
- 从python2迁移到3，支持python3.8
- 增加线程模式
- 增加协程模式
- 原始的项目中读取namp-service-probes过于缓慢，进行重构增加json的缓存

## 思路
```
使用nmap自带的指纹去除nmap特征后进行服务识别,识别思路是先进行一次socket连接,接受服务器的welcome banner
如果welcome banner在设置的一定时间内没有收到,那么根据常见端口发送探测报文
如果还是没有根据nmap probe中的数据逐条发送数据
如果不在指纹库中的最后就返回unkown的结果
```

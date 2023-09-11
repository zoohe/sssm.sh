# shadowsocks server with v2ray-plugin multi-user manager script
使用v2ray-plugin插件的Shadowsocks服务器的多用户管理脚本  
(s)hadow(s)ocks (s)erver with v2ray-plugin multi-user (m)anager script  

这个脚本包含了我4年对shadowsocks+v2ray-plugin+nginx的全部理解  

本脚本硬性需求：  
1. IPv4证书 (可在ZeroSSL免费申请)  
2. Debian/Ubuntu x86_64  
3. Nginx (使用 apt install nginx 或 lnmp.org 安装)  

本脚本能实现：  
简洁易懂快捷方便的多用户管理(添加删除用户)  
针对单个用户的流量监控与限制(达量自动断网)  
自动生成SS以及Nginx的配置文件  
自动生成Windows/macOS/Android/iOS四端的用户配置SS链接  
自动生成客户端下载链接  
你用就知道了！  

本脚本缺点：  
初次执行劝退99.99%潜在用户(啊！？要导入IP证书！？)  
不支持上千名用户的情况  

ss+v2ray-plugin缺点：  
不支持UDP，包括UoT。  

使用方法：  
先去ZeroSSL.com申请一个免费的IP证书  
然后下载sssm.sh，创建一个/home/sssm目录，把sssm.sh放进去，然后使用root运行。  
```
mkdir /home/sssm && wget --no-check-certificate -q -O /home/sssm/sssm.sh "https://github.com/yeyingorg/sssm.sh/raw/main/sssm.sh" && chmod +x /home/sssm/sssm.sh && bash /home/sssm/sssm.sh
```
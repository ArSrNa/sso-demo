# ArCIAM SSO代码示例

集成Express，redis，jwt实现的单点登录

**仅供测试使用！！！请勿带入生产环境，造成后果一切自负！！！**

`keys/public.pem` 为公钥，用于验签使用，公开给所有验证用的服务端使用。

`keys/private.pem`为私钥，用于签发使用，保存在登录的服务器不能泄露。

公私钥请自行生成，使用RS512算法，需要2048位长度的公私钥对。

# 功能特性

- 多key随机切换保证安全
- 使用jwt客户端存储token，减少服务器压力
- 服务端使用redis，高速检索用户名密码

# 后端

## 安装

`npm i`

安装所有后端依赖

`node index`

启动后端

# 前端

打开 `front/index.html`即可

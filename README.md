# ArCIAM SSO代码示例

集成Express，redis，jwt实现的单点登录

**仅供测试使用！！！请勿带入生产环境，造成后果一切自负！！！**

`keys/{uuid}/public.pem` 为公钥，用于验签使用，公开给所有验证用的服务端使用。

`keys/{uuid}/private.pem`为私钥，用于签发使用，保存在登录的服务器不能泄露。

公私钥请自行生成，使用RS512算法，需要2048位长度的公私钥对。可参考[在线RSA密钥对生成工具 - UU在线工具 (uutool.cn)](https://uutool.cn/rsa-generate/)

`.env`里面的配置用于邮件发送和其他功能，请按需设置

# TODOs

- 邮箱验证码验证
- 忘记密码验证
- 数据库改用MySQL

# 功能特性

- access_token多key随机切换保证安全
- 使用jwt客户端存储token，减少服务器压力
- 服务端使用redis，高速检索用户名密码
- 双token方案，提升access_token安全性（此token也是随机key）

# 后端

## 配置

在 `.env.example`里面查看示例

然后新建 `.env`文件，按照示例内容填写相应内容

## 安装

`npm i`

安装所有后端依赖

`node index`

启动后端

# 前端

打开 `front/index.html`即可

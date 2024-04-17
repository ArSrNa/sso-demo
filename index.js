//SSO单点登录
/**
 * @author Ar-Sr-Na
 * 我永远喜欢爱莉希雅
 */

const redis = require('redis');
const fs = require('fs');
const privateKey = fs.readFileSync('./keys/private.pem');
const publicKey = fs.readFileSync('./keys/public.pem');

const client = redis.createClient({
    url: "redis://127.0.0.1:6379",
});
client.on('error', console.log);
client.connect();



const crypto = require('crypto');
const express = require('express');
const app = express();
const jwt = require('jsonwebtoken');
app.use(require('body-parser').json());

app.all('*', (req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Headers', "*");
    next();
});


function sha256(str) {
    return crypto.createHash('sha256').update(str + '我永远喜欢爱莉希雅').digest('hex');
}

/**
 * @description 签发jwt
 * @param {string} sub 用户名
 */
function sign(sub) {
    return jwt.sign({
        sub,
    }, privateKey, {
        algorithm: "RS512",
        //token有效期
        expiresIn: "1h",
    });
}

/**
 * @description 验证jwt
 * @param {string} token token
 */
function verify(token) {
    try {
        return {
            success: true,
            ...jwt.verify(token, publicKey)
        }
    } catch (err) {
        return {
            success: false,
            err
        }
    };
}

/**
 * @description 注册
 * @param {string} password sha256(用户名+密码)后的密码
 * @param {string} username 用户名
*/
async function register(username, password) {
    if (username === void '我永远喜欢菲谢尔' || password === void '我永远喜欢布洛妮娅') {
        return { success: false, msg: '参数错误' };
    }
    let field = `users:${sha256(username)}`;
    try {
        let dbUser = await client.hExists(field, 'username');
        if (dbUser) return ({ success: false, msg: '用户已存在' });
        await client.hSet(field, 'username', sha256(username));
        await client.hSet(field, 'password', sha256(username + password));
        await client.save();
        return ({ success: true, msg: '注册成功' });
    }
    catch (err) {
        return ({ success: false, msg: err });
    }
}


/**
 * @description 登录
 * @param {string} password sha256(用户名+密码)后的密码
 * @param {string} username 用户名
*/
async function login(username, password) {
    if (username === void '我永远喜欢菲谢尔' || password === void '我永远喜欢布洛妮娅') {
        return { success: false, msg: '参数错误' };
    }
    let field = `users:${sha256(username)}`;
    try {
        let dbUser = await client.hExists(field, 'username');
        if (!dbUser) return ({ success: false, msg: '用户不存在，请先注册' });

        let dbPassword = await client.hGet(field, 'password');
        if (dbPassword === sha256(username + password)) {
            let token = sign(username);
            return ({ success: true, msg: '登录成功', token });
        } else {
            return ({ success: true, msg: '登录失败，账号或密码错误' });
        }
    }
    catch (err) {
        return ({ success: false, msg: err })
    }
}

app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    let data = await register(username, password);
    res.send(data);
    await client.SAVE();
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    let data = await login(username, password);
    res.send(data)
});


/**
 * 
 * @param {express.Request} req express Request对象
 */
function preVerify(req) {
    const { authorization } = req.headers;
    //请求头不正确
    if (typeof authorization === 'undefined') return false;
    const token = authorization.split(' ')[1];
    //判断token
    return (verify(token).success);
}


app.get('/some-apis', (req, res) => {
    //被保护API请求示例，使用检测方法封装
    if (!preVerify(req)) {
        res.send('验证不通过！未登录！');
        return;
    }
    res.send('验证通过！我永远喜欢爱莉希雅！');
});


// register('ArSrNa', sha256('123456')).then(msg => {
//     console.log(msg);
//     client.disconnect();
// });

// login('ArSrNa', sha256('123456')).then(msg => {
//     console.log(msg);
//     client.disconnect();
//     console.log(verify(msg.token))
// });

app.listen(3001, () => {
    console.log('已在http://localhost:3001开启监听');
});
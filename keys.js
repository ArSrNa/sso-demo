const { generateKeyPairSync } = require('crypto');
const fs = require('fs');
const path = require('path');

module.exports.kid = [
    '32af72fd1c3342b48276646a99f89926',
    '907beb4278b74bffbfef135bcb146ac8',
    '2ab4f4da0fe64615a8f6f2083917ac21',
    '522fe648a96c4d518429ba87136545e1',
    '8687c8e2cf8c4337904d8bd8ef744006',
    '362e0cc47fc649c492effc1af72e980b',
    /* 备用uuid库
    '85189f79931343b9a6c24624d559de84',
    'd4b57e8f48d54330a4a87b26580dca50',
    'cac10ab666394ce880c4bf225bbc8f52',
    '70c743de961d4e93b630abeb41d85514',
    */
];

// console.log(keys);

function randomString(e) {
    e = e || 32;
    var t = "ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678",
        a = t.length,
        n = "";
    for (i = 0; i < e; i++) n += t.charAt(Math.floor(Math.random() * a));
    return n
}

function generateKeys(uuids) {
    for (let uuid of uuids) {
        let p = `./keys/${uuid}/`
        fs.mkdirSync(p);
        const { publicKey, privateKey } = generateKeyPairSync('rsa', {
            modulusLength: 2048,
            publicKeyEncoding: {
                type: 'spki',
                format: 'pem'
            },
            privateKeyEncoding: {
                type: 'pkcs8',
                format: 'pem'
            }
        });
        fs.writeFileSync(path.join(p, 'private.pem'), privateKey);
        fs.writeFileSync(path.join(p, 'public.pem'), publicKey);
    }
}

// generateKeys(['2ab4f4da0fe64615a8f6f2083917ac21',
//     '522fe648a96c4d518429ba87136545e1',
//     '85189f79931343b9a6c24624d559de84',
//     'd4b57e8f48d54330a4a87b26580dca50',
//     '8687c8e2cf8c4337904d8bd8ef744006',
//     '362e0cc47fc649c492effc1af72e980b',
//     'cac10ab666394ce880c4bf225bbc8f52',]);
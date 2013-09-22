function add64(a, b) {
    var l = a.l + b.l;
    var h = a.h + b.h;
    if(l > 0xffffffff) {
        h = h + 1;
    }
    return {l: l >>> 0, h: h >>> 0};
}

function sub64(a, b) {
    var l = ((~b.l) >>> 0) + 1;
    var h = (~b.h) >>> 0;
    if(l > 0xffffffff) {
        ++h;
    }
    return add64(a, {l: l >>> 0, h: h >>> 0});
}

function xor64(a, b) {
    return {l: (a.l ^ b.l) >>> 0, h: (a.h ^ b.h) >>> 0};
}

function rotL64(x, n) {
    n = n % 64;
    if(n == 32) {
        return {l: x.h, h: x.l};
    } else if(n == 0) {
        return x;
    } else if(n > 32) {
        n -= 32;
        var tmp = x.l;
        x.l = x.h;
        x.h = tmp;
    }
    return {l: ((x.l << n) | (x.h >>> (32-n))) >>> 0,
            h: ((x.h << n) | (x.l >>> (32-n))) >>> 0};
}

function rotR64(x, n) {
    n = n % 64;
    if(n == 32) {
        return {l: x.h, h: x.l};
    } else if(n == 0) {
        return x;
    } else if(n >= 32) {
        n -= 32;
        var tmp = x.l;
        x.l = x.h;
        x.h = tmp;
    }
    return {l: ((x.l >>> n) | (x.h << (32-n))) >>> 0,
            h: ((x.h >>> n) | (x.l << (32-n))) >>> 0};
}

var keyConst = {l: 0xA9FC1A22, h: 0x1BD11BDA};

// Encrypt a block using 256 bit threefish. The result is stored in blockout
// as well as returned, to avoid unnecessary allocations when encrypting many
// blocks.
function encrypt256(key, tweak, blockin, blockout) {
    var k4 = xor64(keyConst, xor64(key[0],
             xor64(key[1],   xor64(key[2], key[3]))));
    var k = [key[0], key[1], key[2], key[3], k4];
    var t = [tweak[0], tweak[1], xor64(tweak[0], tweak[1])];
    var a = add64(blockin[0], key[0]), 
        b = add64(add64(blockin[1], key[1]), tweak[0]),
        c = add64(add64(blockin[2], key[2]), tweak[1]),
        d = add64(blockin[3], key[3]);

    for(var r = 2; r < 20; r += 2) {
        a = add64(a, b); b = xor64(rotL64(b, 14), a);
        c = add64(c, d); d = xor64(rotL64(d, 16), c);
        a = add64(a, d); d = xor64(rotL64(d, 52), a);
        c = add64(c, b); b = xor64(rotL64(b, 57), c);
        a = add64(a, b); b = xor64(rotL64(b, 23), a);
        c = add64(c, d); d = xor64(rotL64(d, 40), c);
        a = add64(a, d); d = xor64(rotL64(d,  5), a);
        c = add64(c, b); b = xor64(rotL64(b, 37), c);
        a = add64(a, k[(r-1) % 5]);
        b = add64(add64(b, k[r % 5]), t[(r-1) % 3]);
        c = add64(add64(c, k[(r+1) % 5]), t[r % 3]);
        d = add64(add64(d, k[(r+2) % 5]), {l: r-1, h: 0});
        a = add64(a, b); b = xor64(rotL64(b, 25), a);
        c = add64(c, d); d = xor64(rotL64(d, 33), c);
        a = add64(a, d); d = xor64(rotL64(d, 46), a);
        c = add64(c, b); b = xor64(rotL64(b, 12), c);
        a = add64(a, b); b = xor64(rotL64(b, 58), a);
        c = add64(c, d); d = xor64(rotL64(d, 22), c);
        a = add64(a, d); d = xor64(rotL64(d, 32), a);
        c = add64(c, b); b = xor64(rotL64(b, 32), c);
        a = add64(a, k[r % 5]);
        b = add64(add64(b, k[(r+1) % 5]), t[r % 3]);
        c = add64(add64(c, k[(r+2) % 5]), t[(r+1) % 3]);
        d = add64(add64(d, k[(r+3) % 5]), {l: r, h: 0});
    }
    blockout[0] = a; blockout[1] = b; blockout[2] = c; blockout[3] = d;
    return blockout;
}

function decrypt256(key, tweak, blockin, blockout) {
    var k4 = xor64(keyConst, xor64(key[0],
             xor64(key[1],   xor64(key[2], key[3]))));
    var k = [key[0], key[1], key[2], key[3], k4];
    var t = [tweak[0], tweak[1], xor64(tweak[0], tweak[1])];
    var a = blockin[0], b = blockin[1], c = blockin[2], d = blockin[3];

    for(var r = 18; r >= 2; r -= 2) {
        a = sub64(a, k[r % 5]);
        b = sub64(b, add64(k[(r+1) % 5], t[r % 3]));
        c = sub64(c, add64(k[(r+2) % 5], t[(r+1) % 3]));
        d = sub64(d, add64(k[(r+3) % 5], {l: r, h: 0}));
        d = rotR64(xor64(d, a), 32); a = sub64(a, d);
        b = rotR64(xor64(b, c), 32); c = sub64(c, b);
        b = rotR64(xor64(b, a), 58); a = sub64(a, b);
        d = rotR64(xor64(d, c), 22); c = sub64(c, d);
        d = rotR64(xor64(d, a), 46); a = sub64(a, d);
        b = rotR64(xor64(b, c), 12); c = sub64(c, b);
        b = rotR64(xor64(b, a), 25); a = sub64(a, b);
        d = rotR64(xor64(d, c), 33); c = sub64(c, d);
        a = sub64(a, k[(r-1) % 5]);
        b = sub64(b, add64(k[r % 5], t[(r-1) % 3]));
        c = sub64(c, add64(k[(r+1) % 5], t[r % 3]));
        d = sub64(d, add64(k[(r+2) % 5], {l: r-1, h: 0}));
        d = rotR64(xor64(d, a),  5); a = sub64(a, d);
        b = rotR64(xor64(b, c), 37); c = sub64(c, b);
        b = rotR64(xor64(b, a), 23); a = sub64(a, b);
        d = rotR64(xor64(d, c), 40); c = sub64(c, d);
        d = rotR64(xor64(d, a), 52); a = sub64(a, d);
        b = rotR64(xor64(b, c), 57); c = sub64(c, b);
        b = rotR64(xor64(b, a), 14); a = sub64(a, b);
        d = rotR64(xor64(d, c), 16); c = sub64(c, d);
    }
    blockout[0] = sub64(a, k[0]);
    blockout[1] = sub64(b, add64(k[1], t[0]));
    blockout[2] = sub64(c, add64(k[2], t[1]));
    blockout[3] = sub64(d, k[3]);
    return blockout;
}

var _skeincfg256 = [{l:0x33414853,h:1},{l:256,h:0},{l:0,h:0},{l:0,h:0}];
var _zero256 = [{l:0,h:0},{l:0,h:0},{l:0,h:0},{l:0,h:0}];

function newTweak(type) {
    return setFirst(true, setType(type, [{l:0,h:0},{l:0,h:0}]));
}

// Relevant types for "normal" Skein
var _t_key = 0;
var _t_config = 4;
var _t_message = 48;
var _t_output = 63;

function setType(type, tweak) {
    tweak[1].h = ((tweak[1].h & ~(63 << 24)) | (type << 24)) >>> 0;
    return tweak;
}

function setFirst(first, tweak) {
    if(first) {
        tweak[1].h = (tweak[1].h | (1 << 30)) >>> 0;
    } else {
        tweak[1].h = (tweak[1].h & (~(1 << 30))) >>> 0;
    }
    return tweak;
}

function setLast(first, tweak) {
    if(first) {
        tweak[1].h = (tweak[1].h | (1 << 31)) >>> 0;
    } else {
        tweak[1].h = (tweak[1].h & (~(1 << 31))) >>> 0;
    }
    return tweak;
}

function addBytes(bytes, tweak) {
    tweak[0] = add64(tweak[0], {l:bytes, h:0});
    return tweak;
}

function init256(key) {
    var t = addBytes(32, cfgTweak());
    return xor(encrypt256(key, t, _skeincfg256, [0,0,0,0]), _skeincfg256);
}

var _zeroPadding = '\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0';

function hash256(key, msg) {
    var tweak = newTweak(_t_message);
    var out = [0,0,0,0];
    var lastlen = msg.length % 32 ? msg.length % 32 : (msg.length ? 32 : 0);
    var lastblock = Math.ceil(msg.length / 32) - 1;
    if(lastblock < 0) {
        lastblock = 0;
    }
    msg = msg + _zeroPadding;
    key = init256(key);
    for(var i = 0; i <= lastblock; ++i) {
        var block = toBlock256(msg.substring(0,32));
        msg = msg.substring(32);
        if(i == lastblock) {
            setLast(true, tweak);
            addBytes(lastlen, tweak);
        } else {
            addBytes(32, tweak);
        }
        encrypt256(key, tweak, block, out);
        key = xor(out, block);
        setFirst(false, tweak);
    }
    var finalTweak = addBytes(8, setLast(true, newTweak(_t_output)));
    return encrypt256(key, finalTweak, _zero256, out);
}

function toBlock256(str) {
    var block = [0,0,0,0];
    for(var i = 0; i < 32; i += 8) {
        var l = ((str.charCodeAt(i) & 255)
              | ((str.charCodeAt(i+1) & 255) << 8)
              | ((str.charCodeAt(i+2) & 255) << 16)
              | ((str.charCodeAt(i+3) & 255) << 24)) >>> 0;
        var h = ((str.charCodeAt(i+4) & 255)
              | ((str.charCodeAt(i+5) & 255) << 8)
              | ((str.charCodeAt(i+6) & 255) << 16)
              | ((str.charCodeAt(i+7) & 255) << 24)) >>> 0;
        block[i/8] = {l:l,h:h};
    }
    return block;
}

function cfgTweak() {return setLast(true, newTweak(_t_config))};



// XOR an array of 64 bit words.
function xor(a, b) {
    var c = [];
    for(var i in a) {
        c[i] = xor64(a[i], b[i]);
    }
    return c;
}

var _hex = '0123456789abcdef';

// Shows a block as a list of 64 bit words.
function showWords(ws) {
    var s = '';
    for(var i in ws) {
        var word = ws[i].h;
        for(var j = 0; j < 4; ++j) {
            var w = word >>> (24-j*8);
            s += _hex[(w >>> 4) & 0x0f] + _hex[w & 0x0f];
        }
        var word = ws[i].l;
        s += "."
        for(var j = 0; j < 4; ++j) {
            var w = word >>> (24-j*8);
            s += _hex[(w >>> 4) & 0x0f] + _hex[w & 0x0f];
        }
        s += " ";
    }
    return s;
}

// Shows a block as a string of bytes.
function showHex(ws) {
    var s = '';
    for(var i in ws) {
        var w = ws[i].l;
        for(var j = 0; j < 4; ++j) {
            s += _hex[(w >>> 4) & 0x0f] + _hex[w & 0x0f];
            w = w >>> 8;
        }
        var w = ws[i].h;
        for(var j = 0; j < 4; ++j) {
            s += _hex[(w >>> 4) & 0x0f] + _hex[w & 0x0f];
            w = w >>> 8;
        }
    }
    return s;
}

function toBytes(words) {
    var bytes = [];
    for(var i = 0; i < words.length; ++i) {
        var b = words[i];
        bytes.push(String.fromCharCode(b.l & 0xff));
        bytes.push(String.fromCharCode((b.l >>> 8) & 0xff));
        bytes.push(String.fromCharCode((b.l >>> 16) & 0xff));
        bytes.push(String.fromCharCode((b.l >>> 24) & 0xff));
        bytes.push(String.fromCharCode(b.h & 0xff));
        bytes.push(String.fromCharCode((b.h >>> 8) & 0xff));
        bytes.push(String.fromCharCode((b.h >>> 16) & 0xff));
        bytes.push(String.fromCharCode((b.h >>> 24) & 0xff));
    }
    return bytes.join('');
}

// Calculate the 256 bit Skein digest of a given message.
// The message is assumed to be a string where each character represents
// a single byte.
function skein256(message) {
    return toBytes(hash256(_zero256, message));
}

// Calculate the 256 bit Skein MAC of a given message.
// The key and message are both assumed to be strings where each character
// represents a single byte. The key must be 256 bits long.
function skeinMAC256(key, message) {
    key = toBlock256(key);
    var t = addBytes(32, setLast(true, newTweak(_t_key)));
    var enc = encrypt256(_zero256, t, key, [0,0,0,0]);
    return toBytes(hash256(xor(key, enc), message));
}

// Encrypt a message using 256 bit Threefish in CBC mode. The key, message and
// IV are assumed to be strings of bytes whose length is a multiple of 32.
function cbc(key, message, iv) {
    var block;
    var out = [];
    var t = [{l:0,h:0},{l:0,h:0}];
    iv = toBlock256(iv);
    key = toBlock256(key);
    while(message.length) {
        block = toBlock256(message.substring(0,32));
        message = message.substring(32);
        encrypt256(key, t, xor(block, iv), iv);
        out.push(iv[0]);
        out.push(iv[1]);
        out.push(iv[2]);
        out.push(iv[3]);
    }
    return toBytes(out);
}

// Encrypt a message using 256 bit Threefish in CBC mode. The key, message and
// IV are assumed to be strings of bytes whose length is a multiple of 32.
function uncbc(key, message, iv) {
    var block, tmp = [0,0,0,0];
    var out = [];
    var t = [{l:0,h:0},{l:0,h:0}];
    iv = toBlock256(iv);
    key = toBlock256(key);
    while(message.length) {
        block = toBlock256(message.substring(0,32));
        message = message.substring(32);
        decrypt256(key, t, block, tmp);
        tmp = xor(tmp, iv);
        out.push(tmp[0]);
        out.push(tmp[1]);
        out.push(tmp[2]);
        out.push(tmp[3]);
        iv = block;
    }
    return toBytes(out);
}

// A Threefish 256 encryptor. The key is assumed to be a string consisting of
// exactly 32 characters, none of which has a charcode >255.
function Threefish256(key) {
    var tweak = [{l:0,h:0}, {l:0,h:0}];

    // Encrypt a message using CBC with the given IV. Messages whose length is
    // not a multiple of 32 bytes are zero padded.
    this.encryptCBC = function(message, iv) {
        var padlen = 32 - (message.length % 32);
        if(padlen == 32) {
            padlen = 0;
        }
        message = message + _zeroPadding.substring(0, padlen);
        return cbc(key, message, iv);
    };

    // Decrypt a message using CBC with the given IV.
    this.decryptCBC = function(message, iv) {
        return uncbc(key, message, iv);
    };

    // CBC encrypt a message, then prepend the 256 bit SkeinMAC of the
    // cryptotext.
    this.encryptAuthenticated = function(message, iv) {
        var cryptotext = this.encryptCBC(message, iv);
        var macKey = encrypt256(_zero256,tweak,toBlock256(key),[0,0,0,0]);
        var mac = skeinMAC256(toBytes(macKey), cryptotext);
        return mac + cryptotext;
    };

    // Check the signature of a message encrypted using encryptAuthenticated,
    // then decrypt it. Returns null if signature verification fails.
    this.decryptAuthenticated = function(message, iv) {
        var cryptotext = message.substring(32);
        var macKey = encrypt256(_zero256,tweak,toBlock256(key),[0,0,0,0]);
        var mac = skeinMAC256(toBytes(macKey), cryptotext);
        if(mac != message.substring(0,32)) {
            return null;
        }
        return this.decryptCBC(cryptotext, iv);
    };
}

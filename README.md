threefish.js
============

Javascript implementation of the Threefish block cipher and Skein hash function. Currently 256 bits only.


Usage
=====

Keys and messages are all treated as strings of bytes.
The easiest way to use threefish.js is the Threefish256 class:

    var tf = new Threefish256("totally secret 32 bytes long key");
    var iv = "the iv should be 32 bits as well"; // since only CBC is implemented, IVs must be unpredictable!
    var cryptotext = tf.encryptAuthenticated("hello", iv);
    var plaintext = tf.decryptAuthenticated(cryptotext, iv); // plaintext = "hello"
    
    var tf2 = new Threefish256("totally secret 32 bytes long key");
    var cryptotext2 = "x" + cryptotext.substring(1); // cryptotext was tampered with!
    var plaintext2 = tf.decryptAuthenticated(cryptotext2, iv); // plaintext = null
    
    var tf3 = new Threefish256("another key that is not the same");
    var plaintext3 = tf.decryptAuthenticated(cryptotext, iv); // plaintext = null

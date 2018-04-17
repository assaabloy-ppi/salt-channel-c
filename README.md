# Salt-channel-c
[![Build Status](https://travis-ci.org/assaabloy-ppi/salt-channel-c.svg?branch=master)](https://travis-ci.org/assaabloy-ppi/salt-channel-c)
[![Code Coverage](https://codecov.io/gh/assaabloy-ppi/salt-channel-c/branch/master/graph/badge.svg)](https://codecov.io/gh/assaabloy-ppi/salt-channel-c)

About
-----



C implementation of [Salt Channel](https://github.com/assaabloy-ppi/salt-channel). *Salt Channel is "Powered by Curve25519"*

**License:** MIT

## Development
The salt-channel-c is mainly developed using the following tools:
* Ubuntu
* gcc
* CMake
* CMocka
* lcov

### To test the implementation or contribute with development:
1. Install tools
```
$ apt-get install cmake lcov
```
2. Build
```
$ mkdir build
$ cd build
$ cmake ..
$ make
$ make test
```

### Fuzz testing
See the [fuzz-tests directory](fuzz-tests).

### Static analysis
[scan-build](https://clang-analyzer.llvm.org/scan-build.html) can be used to do static code analysis. It requires LLVM and clang to be installed. See **static-analyzer.sh** for an example of how it could be used, if used as in the example a HTML report with potential bugs will be created.

### Importing to eclipse
Eclipse can be used for development and debugging. Assumed that this repository is cloned to your home folder and that the eclipse workspace is located in **~/workspace** the setup could be done similar to this:

1. Clone this repository and initiate the eclipse workspace:

```
$cd ~/
$ git clone https://github.com/assaabloy-ppi/salt-channel-c
$ mkdir -p ~/workspace/salt-channel-c
$ cmake -G "Eclipse CDT4 - Unix Makefiles" ~/salt-channel-c
```

2. In eclipse: **File > Import > General > Existing Projects into Workspace**
3. Check **Select root directory** and chose ~/workspace/salt-channel-c, make sure **Copy projects into workspace** is NOT checked.
4. Press **Finish**.

Note: If any cmake configuration files is modified you need to repeat **step 1**.

### A simple example
An echo salt-channel host is provided. If a message that is sent to the host starts with the byte **0x01** the host will echo the same message to the client.

**Host-side:**
```
$ ./examples/host_echo
Socket created
bind done
Waiting for incoming connections...
Connection accepted
Waiting for client to disconnect.
Waiting for incoming connections...
Salt handshake succeeded.
```
**Client-side:**
```
$ ./examples/client_echo
Connection to 127.0.0.1
Connected successfully - Please enter string
Salt handshake succeeded.
Enter message: Hello
client: Hello
host: Hello
Enter message:

```

## Implementation details

Salt-channel-c is an implementation of the salt-channel over a serial stream. I.e., the expected input data format and the output data format follows the following structure:

    **** Stream message structure ****

    4   Size.
        Four size bytes in Little endian byte order. E.g.:
        Size = 4: sizeBytes[4] = { 0x04, 0x00, 0x00, 0x00 }

    N   Payload

I.e., to send a payload of length **n**, the number of transmitted bytes are **n+4**.

### Thread safety
Salt-channel-c is optimized for portability and does not perform any platform specific memory or threading safety operations. Such operations need to be performed by calling application, if required.
* The library is not thread safe.
* Memory security operations such as memset_s, SecureZeroMemory, mlock/munlock are not performed by the library.

### Goals

* **Non-blocking:**
The salt-channel implementation should be non-blocking. I.e., the implementation must be able to run on a system without threads. However, the user of the implementation may make it blocking depending on user injected I/O implementation. The state of each salt-channel process must be either SUCCESS, PENDING or ERROR.


* **No dynamic memory allocation:**
The salt-channel-c implementation must work on systems with no heap. However, it's up to the user of the implementation to decide whether to use dynamic memory allocation since all used buffers are injected.


* **Slow I/O:**
Do cryptographic computations during I/O. If the I/O is slow, some of the cryptographic computations can be calculated while waiting for I/O:

    * Client sends the ephemeral public encryption key in message M1.
    * Host received the client key and immediately sends the host key in message M2.
    * While I/O, calculate the ephemeral key. Immediately after this, start calculating the signature used for M3.
    * Client received the host key and immediately starts calculating this. This can be done while the M3 message is received from the host. Directly after this, the client starts calculating the signature used for M4.
    * Client receives M3 and the host signature. If the signature is valid and the host can be authenticated, the clients send the M4 message containing the clients signature.

### General message structure
Except for message *M1* each message follows this structure:

    **** Salt-channel message structure ****
    2   Header.

    N   Payload.

### TweetNaCl API
The TweetNaCl library is a subset of the NaCl library and the crypto API used for this implementation is available at https://nacl.cr.yp.to/.

**Encryption:**
The encryption API *crypto_box_afternm* requires the first 32 (crypto_secretbox_ZEROBYTES) bytes to be zero (0x00) padded. After encryption the first 16 (crypto_secretbox_BOXZEROBYTES) will be zero (0x00):
```
--> Clear text data must be zero padded:
    clearText[N] = { zeroPadded[32] || clearText[N-32] }
--> Encrypt:
    encryptedAndAuthenticated = { zeroPadded[16] || cipher[N-16] }
```
In order to minimize send data over slow I/O channels the 16 zero padded bytes are neglected.

**Decryption:**
The decryption API *crypto_box_open_afternm* requires the first 16 bytes to be zero (0x00) padded. After decryption the first 32 bytes will be zero.
```
--> Cipher data must be zero padded:
    encryptedAndAuthenticated[N] = { zeroPadded[16] || cipher[N-16] }
--> Decrypt:
    clearText[N-32] = { zeroPadded[32] || clearText[N-32] }
```

Both the *crypto_box_afternm* and the *crypto_box_open_afternm* methods seems to allow "in-place" operation. I.e., there is no need for two buffer (one for cipher, one for clear text). However, if using salt-channel-c, the user must verify that the underlying cryptographic library handles this.


**Hashing:**
SHA512 is used for hashing and the size of a hash is 64 bytes. If the message to hash is larger than 64 bytes, the API allows for putting the hash where the original message was. I.e.: We don't need a specific storage for the hash, if we don't want to save the original message. This seems to be a hidden feature, the next version should not rely on this feature. When chosing a crypto library, make sure that this feature is supported.

**Signing:**
The TweetNaCl API doesn't allow to only generate a signature (64 bytes) or verify a message with the signature separated from the message. Further, the API requires a separate buffer to put the signed and unsigned message in.
```
dataToSign = { data[n] }                     -> signedData = { signature[64} || data[n] }
dataToVerify = { signature[64} || data[n] }  -> verified = { data{n] }
```

The TweetNaCl seems to allow for signing a message and putting in in the original location, i.e.:
```
dataToSign = { reserved[64] || data[n] }     -> signedData { signature[64] || data[n] }
```

For later update, possible only libsodium API will be supported and the usage of *crypto_sign_detached* and *crypto_verify_detached* will be used. If changing to this, there is no relying on the hidden feature mentioned above.

## Message wrapping
Due to the TweetNaCl api the wrapping is a little bit complex. Further, some headers are introduced. Assuming the wrapping of a message of size **n**. The clear text message to wrap have the following layout:
```
wrappedClear = { header[2] || time[4] || msg[n] }
```
To encrypt this, there MUST be 32 bytes of zero padding before the message.
```
wrappedToDecrypt = { zeroPadded[32] || wrappedClear[6 + n] }
```
This is then encrypted. After the encryption, the first 16 bytes will be zero padded.
```
encrypted = { zeroPadded[16] || cipher[16 + 6 + n] }
```
Hence, in order to encrypt a message of length **n**, there must be 38 bytes available in the buffer before the message. After the encryption, the message is wrapped with a header and size bytes:
```
wrappedEncrypted = { zeroPadded[10] || sizeBytes[4] || header[2] || cipher[16 + 6 + n] }
```

The overhead of a wrapped message is therefore 38 bytes. The zeroPadded part is not sent.
The length of the wrapped message to send is: **wrapedToSend = 4 + 2 + 16 + 6 = 28 bytes**

## Message unwrapping
When receiving an encrypted and wrapped message, the following format is expected:
```
wrappedEncrypted = { header[2] || cipher[16 + 6 + n] }
```
In order to decrypt this, we need 16 bytes of zeros before the cipher. Therefore, when reading an encrypted message, it will be read **14** bytes into the buffer. First, the header bytes are verified, if they are OK, the message are encrypted.
```
wrappedEncrypted = { reservedForPadding[14] || header[2] || cipher[16 + 6 + n] }
    -> verifyHeader(header)
    -> header = { 0x00, 0x00 }
wrappedEncrypted = { zeroPadded[16] || cipher[16 + 6 + n] }
    -> decrypt(wrappedEncrypted)
wrappedClear = { zeroPadded[32] || header[2] || time[4] || message[n] }
```
Hence, in order to read a clear text message of length **n**, we need a buffer that is 38 bytes larger. The clear text message is then located **38** bytes in the buffer.
## Handshake procedure
If looking in the code, there are a lot of magic offsets. These are due to the crypto API and in an effort to keep the required handshake buffer to a minimum. The data to sign for authentication is:
```
dataToSign = { sigPrefix[8] || m1Hash[64] || m2Hash[64 ] }
```

### Host handshake procedure
1. Session initialization
The ephemeral keypair is calculated in the beginning of the handshake buffer. These first 64 bytes are later used for the authentication (signing).
```
buffer = { ek_pub[32] || ek_sec[32] }
```
2. Read M1 to buffer[72], these will allow for creating the buffer for signing mentioned above.
```
buffer = { ek_pub[32] || ek_sec[32] || reservedForSigPrefix[8] || m1[42 or 74] }
```
M1 is then verified and the hash is calculated on the original message. We know at this point how big the size of M2 will be which we reserve in the buffer. Directly after this we copy the clients public encryption key directly after this. This one is used later for calculating the shared secret for the session.
```
buffer = { ek_pub[32] || ek_sec[32] || reservedForSigPrefix[8] || m1Hash[64] || reservedForM2[42] || clientEkPub[32] }
```

3. Create M2 to buffer[200]. M2 is in clear text, and the size bytes are also created into M2. When creating M2, the hash is also calculated.
```
buffer = { ek_pub[32] || ek_sec[32] || reservedForSigPrefix[8] || m1Hash[64] || m2Hash[64] || m2[42] }
```
If a **noSuchServer** condidition occured in M1, the session will be closed immidiately after M2 is sent, and the handshake method will return error.
4. Start sending M2.
5. Calculate the shared secret for the session:
```
sharedSecret = crypto_box_beforenm(ek_common, &buffer[242], &buffer[32])
```
*ek_common* is saved in the channel structure.
6. Continue sending M2 if not completed.
7. Calculate the signature for authentication.
The public and secret encryption keys are no longer needed since we know have calculated the session key. The sig1Prefix is copied into reservedForSigPrefix.
```
buffer = { ek_pub[32] || ek_sec[32] || sig1Prefix[8] || m1Hash[64] || m2Hash[64] }
sign(buffer) =>
buffer = { signature[64} || sig1Prefix[8] || m1Hash[64] || m2Hash[64] }
```
Since we need 38 bytes overhead for encrypting and wrapping the M3 message, which include the public signature key of the host, and the signature will be copied to buffer[238].
```
buffer = { signature[64} || sig1Prefix[8] || m1Hash[64] || m2Hash[64] || reserved[38] , m3[96] }
m3 = { hostSigPub[32] || signature[64] }
```
7. Wrap the M3 message.
```
wrap(buffer[238])
buffer = { signature[64} || sig1Prefix[8] || m1Hash[64] || m2Hash[64] || zeroPadded[10] || m3WithSize[124] }
m3WithSize = { m3SizeBytes[4] || header[2] || m3Cipher[118] }
```
8. Send M3. Since we need 14 bytes if padding to unwrap M4, we read M4 into buffer[214].
```
buffer = { signature[64} || sig1Prefix[8] || m1Hash[64] || m2Hash[64] || reserved[14] , header[2] , m3WrappedAndEncrypted[118] }
    -> Verify header and unwrap
buffer = { signature[64} || sig1Prefix[8] || m1Hash[64] || m2Hash[64] || zeroPadded[32] || header[2] || time[4] || m4Clear[96] }
m4Clear = { clientSigPub[32] || signature[64] }
    -> Copy clientSigPub to channel structure.
```
9. The signature in the M3 message is then verified. The sig2Prefix is copied into reservedForSigPrefix and the signature from M4 is copied to signature. When verifying the signature, the signed message will be copied to another location, we chose to put it directly after m2Hash (buffer[200]) since we don't need that data anymore.
```
buffer = { m4signature[64} || sig2Prefix[8] || m1Hash[64] || m2Hash[64] || zeroPadded[32] || header[2] || time[4] || clientSigPub[32] || signature[64] }
    -> verify signature
buffer = { m4signature[64] || sig2Prefix[8] || m1Hash[64] || m2Hash[64] || m1Hash[64] || m2Hash[64] }
```

Hence, the smallest handshake buffer required for a host handshake procedure is **64 + 8 + 64 + 64 + 64 + 64 = 238 bytes**.

10. Authentication done.

### Client handshake procedure.
Not documented yet.

# Salt-channel-c

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
$ apt-get install cmake libcmocka-dev lcov
```
2. Build
```
$ mkdir build
$ cd build
$ cmake ..
$ make
$ make test
```

### Importing to eclipse
Eclipse can be used for development and debugging. Assumed that this repository is cloned to your home folder and that the eclipse workspace is located in **~/workspace** the setup could be done similar to this:

1. Clone this repository and initiate the eclipse workspace:

```
$cd ~/
$ git clone https://github.com/assaabloy-ppi/salt-channel-c
$ mkdir -p ~/workspace/salt-channel-c
$ cmake -G "Eclipse CDT4 - Unix Makefiles" ~/salt-channel-c

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
        Four size bytes in Littleendian byte order. E.g.:
        Size = 4: sizeBytes[4] = { 0x04, 0x00, 0x00, 0x00 }
    

### Goals

* **Non-blocking:**
The salt-channel implementation should be non-blocking. I.e., the implementation must be able to run on a system without threads. However, the user of the implementation may make it blocking depending on user injected I/O implementation. The state of each salt-channel process must be either SUCCESS, PENDING or error.


* **No dynamic memory allocation:**
The salt-channel-c implementation must work on systems with no heap. However, it's up to the user of the implementation to decide whether to use dynamic memory allocation since all used buffers are injected.


* **Slow I/O:**
Do cryptographic computations during I/O. If the I/O is slow, some of the crypthographic computations can be calculated while waiting for I/O:

    * Client sends the ehpemeral public encryption key in message M1.
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
The encryption API crypto_box_afternm requires the first 32 (crypto_secretbox_ZEROBYTES) bytes to be zero (0x00) padded. After encryption the first 16 (crypto_secretbox_BOXZEROBYTES) will be zero (0x00):
```
--> Clear text data must be zero padded:
    clearText[N] = { zeroPadded[32] , clearText[N-32] }
--> Encrypt:
    encryptedAndAuthenticated = { zeroPadded[16] , cipher[N-16] }
```
In order to minimize send data over slow I/O channels the 16 zero padded bytes are neglected.

**Decryption:**
The decryption API crypto_box_open_afternm requires the first 16 bytes to be zero (0x00) padded. After decryption the first 32 bytes will be zero.
```
--> Cipher data must be zero padded:
    encryptedAndAuthenticated[N] = { zeroPadded[16] , cipher[N-16] }
--> Decrypt:
    clearText[N-32] = { zeroPadded[32] , clearText[N-32] }
```

Both the crypto_box_afternm and the crypto_box_open_afternm methods allows to perform the cryptographic operations directly on the buffers.


**Hashing:**
sha512 is used for hashing and the size of a hash is 64 bytes. If the message to hash is larger than 64 bytes, the API allows for putting the hash where the original message was. I.e.: We don't need a specific storage for the hash, if we dont want to save the original message.

**Signing:**
The TweetNaCl API doesn't allow to only generate a signature (64 bytes) or verify a message with the signature separated from the message. Further, the API requires a seperate buffer to put the signed and unsigned message in.


### Server handshaking procedure

TODO: Write or refer to  code.

### Client handshaking procedure

TODO: Write or refer to code.
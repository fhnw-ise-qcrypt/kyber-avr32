

quantum key exchange in the GOSH

User Manual prior to programming the acutal thing

---

## Build

```bash
mkdir build && cd build
cmake ..
cmake --build .
```

---

Prepare for example below:

```bash
mkdir alice
mkdir bob
cp ./ref/kex-init ./ref/kex-pub alice
cp ./ref/kex-init ./ref/kex-pub bob
```

Open two command lines and navigate to alice and bob.

---

## Usage

### 1. Initialize a static keypair for both participants

**Alice**
```bash
$ alice > ./kex-init
[ ok  ] wrote 1632 bytes to ./SKA.key
[ ok  ] wrote 800 bytes to ./PKA.key
[ ok  ] my public key is:
aa00aa00aa00
```

**Bob**
```bash
$ bob > ./kex-init
[ ok  ] wrote 1632 bytes to ./SKA.key
[ ok  ] wrote 800 bytes to ./PKA.key
[ ok  ] my public key is:
00bb00bb00bb
```

### 2. Exchange each public key

**Alice**
```bash
$ alice > ./kex-pub -p 00bb00bb00bb
```

**Bob**
```bash
$ bob > ./kex-pub -p aa00aa00aa00
```

### 3. Start the Kex Exchange with Alice (or Bob)
**Alice**
```bash
$ alice > ./kex-pub -A
[ ok  ] read 800 / 2400 bytes from ./PKB.key
[ ok  ] wrote 32 bytes to ./TK.key
[ ok  ] wrote 1632 bytes to ./ESKA.key
Send to other Party:
00112233445566778899aabbccddeeff
```

### 4. Send encrypted message to Bob
**Bob**
```bash
$ bob > ./kex-pub -B 00112233445566778899aabbccddeeff
[ ok  ] read 1568 / 3136 bytes from stdin
[ ok  ] read 1632 / 2400 bytes from ./SKA.key
[ ok  ] read 800 / 2400 bytes from ./PKB.key
Send to other Party:
ffeeddccbbaa9988776655443321100
[1536 bytes]
Common Shared Secret:
00deadbeef00
[32 bytes]
[ ok  ] wrote 32 bytes to ./COMMON.key
```

### 5. Send encrypted message back to Alice
**Alice**
```bash
$ alice > ./kex-pub -C ffeeddccbbaa9988776655443321100
[ ok  ] read 60 / 2400 bytes from ./TK.key
[ ok  ] read 1632 / 2400 bytes from ./SKA.key
[ ok  ] read 1632 / 2400 bytes from ./ESKA.key
[ ok  ] read 1536 / 3072 bytes from stdin
Common Shared Secret:
00deadbeef00
[32 bytes]
[ ok  ] wrote 32 bytes to ./COMMON.key
```

### 6. Key exchange successful

Now both Alice and Bob should have the same key inside `COMMON.key`.

---


```c
kex_ake_initA   ( ake_senda, tk, eska, pkb); // Run by Alice
kex_ake_sharedB ( ake_sendb, kb, ake_senda, skb, pka); // Run by Bob
// kex_ake_sharedB ( ake_sendb, ka, ake_senda, ska, pka); // Run by Bob
kex_ake_sharedA ( ka, ake_sendb, tk, eska, ska); // Run by Alice
```

original:

```c
kex_ake_initA(ake_senda, tk, eska, pkb); // Run by Alice

kex_ake_sharedB(ake_sendb, kb, ake_senda, skb, pka); // Run by Bob

kex_ake_sharedA(ka, ake_sendb, tk, eska, ska); // Run by Alice
```


`kex_ake_initA(ake_senda, tk, eska, pkb);`
- ake_senda (out) = [temp public key of a + ciphertext]
- tk        (out) = shared secret
- eska      (out) = is the secret key for a for this key exchange
- pkb       (in ) = static public key of b

`kex_ake_sharedB(ake_sendb, kb, ake_senda, skb, pka);`
- ake_sendb (out) = 
- kb        (out) = common shared secret key
- ake_senda (in ) = [temp public key of a + ciphertext]
- skb       (in ) = static secret key of b
- pka       (in ) = static public key of a

`kex_ake_sharedA(ka, ake_sendb, tk, eska, ska);`
- ka        (out) = common shared secret key
- ake_sendb (in ) = 
- tk        (in ) = 
- eska      (in ) = 
- ska       (in ) = 

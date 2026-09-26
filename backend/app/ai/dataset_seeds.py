"""Curated snippet/context pairs. Imported names and inputs may be supplied by context.

Examples illustrate classification, not security recommendations or runnable programs.
Four independent API/behavior examples per language/class; five for negatives.
"""

SEEDS = {
    "encryption": {
        "python": [
            ("AESGCM is imported from cryptography; secret and nonce are byte strings.", 'box = AESGCM(secret)\nciphertext = box.encrypt(nonce, payload, header)'),
            ("AES is Crypto.Cipher.AES; session_key is a secret key.", 'cipher = AES.new(session_key, AES.MODE_GCM)\nsealed, tag = cipher.encrypt_and_digest(message)'),
            ("recipient_key is an RSA public key from cryptography; padding and hashes are its primitives.", 'ciphertext = recipient_key.encrypt(\n    document, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),\n                           algorithm=hashes.SHA256(), label=None))'),
            ("Fernet is imported from cryptography.fernet; token_key was provisioned earlier.", 'box = Fernet(token_key)\ntoken = box.encrypt(customer_bytes)'),
        ],
        "java": [
            ("Cipher and GCMParameterSpec are javax.crypto classes; key and iv are supplied.", 'Cipher box = Cipher.getInstance("AES/GCM/NoPadding");\nbox.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));\nbyte[] ciphertext = box.doFinal(payload);'),
            ("Cipher is javax.crypto.Cipher and recipient is an RSA PublicKey.", 'Cipher envelope = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");\nenvelope.init(Cipher.ENCRYPT_MODE, recipient);\nbyte[] sealed = envelope.doFinal(message);'),
            ("Cipher is javax.crypto.Cipher; key and nonce are supplied for ChaCha20-Poly1305.", 'Cipher c = Cipher.getInstance("ChaCha20-Poly1305");\nc.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(nonce));\nbyte[] packet = c.doFinal(input);'),
            ("Cipher and IvParameterSpec come from javax.crypto; the example focuses on one API operation.", 'Cipher c = Cipher.getInstance("AES/CTR/NoPadding");\nc.init(Cipher.ENCRYPT_MODE, secret, new IvParameterSpec(counter));\noutput.write(c.doFinal(buffer));'),
        ],
        "javascript": [
            ("crypto is Node's node:crypto module; key and iv are supplied.", 'const box = crypto.createCipheriv("aes-256-gcm", key, iv);\nconst sealed = Buffer.concat([box.update(payload), box.final()]);'),
            ("publicEncrypt comes from node:crypto and recipientKey contains an RSA public key.", 'const sealed = publicEncrypt(recipientKey, Buffer.from(message));'),
            ("CryptoJS is the crypto-js package; passphrase is supplied by the caller.", 'const token = CryptoJS.AES.encrypt(text, passphrase).toString();'),
            ("crypto is Node's crypto module; secret is a ChaCha20 key and nonce is supplied.", 'const box = crypto.createCipheriv("chacha20-poly1305", secret, nonce, { authTagLength: 16 });\nconst output = Buffer.concat([box.update(input), box.final()]);'),
        ],
        "typescript": [
            ("webcrypto is imported from node:crypto; aesKey is a CryptoKey.", 'const ciphertext: ArrayBuffer = await webcrypto.subtle.encrypt(\n  { name: "AES-GCM", iv }, aesKey, payload);'),
            ("publicEncrypt is from node:crypto; recipient is an RSA KeyObject.", 'const sealed: Buffer = publicEncrypt({ key: recipient }, data);'),
            ("CryptoJS is the crypto-js package; message and passphrase are strings.", 'const encoded: string = CryptoJS.AES.encrypt(message, passphrase).toString();'),
            ("createCipheriv is from node:crypto; bytes contain a file chunk.", 'const stream = createCipheriv("aes-192-cbc", secret, iv);\nconst chunk: Buffer = Buffer.concat([stream.update(bytes), stream.final()]);'),
        ],
    },
    "decryption": {
        "python": [
            ("AESGCM is cryptography's authenticated cipher; tag is included in sealed.", 'box = AESGCM(secret)\nplaintext = box.decrypt(nonce, sealed, header)'),
            ("AES is Crypto.Cipher.AES; nonce and authentication tag came with the ciphertext.", 'cipher = AES.new(session_key, AES.MODE_GCM, nonce=nonce)\nmessage = cipher.decrypt_and_verify(sealed, tag)'),
            ("recipient_key is an RSA private key from cryptography.", 'plaintext = recipient_key.decrypt(\n    ciphertext, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),\n                             algorithm=hashes.SHA256(), label=None))'),
            ("Fernet is cryptography.fernet.Fernet and token is a stored opaque byte string.", 'box = Fernet(token_key)\noriginal = box.decrypt(token)'),
        ],
        "java": [
            ("Cipher is javax.crypto.Cipher; payload contains the GCM authentication tag.", 'Cipher box = Cipher.getInstance("AES/GCM/NoPadding");\nbox.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));\nbyte[] plaintext = box.doFinal(payload);'),
            ("Cipher is javax.crypto.Cipher; recipient is an RSA PrivateKey.", 'Cipher envelope = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");\nenvelope.init(Cipher.DECRYPT_MODE, recipient);\nbyte[] message = envelope.doFinal(sealed);'),
            ("Cipher is javax.crypto.Cipher; key and nonce belong to the received packet.", 'Cipher c = Cipher.getInstance("ChaCha20-Poly1305");\nc.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(nonce));\nbyte[] original = c.doFinal(packet);'),
            ("Cipher and IvParameterSpec are javax.crypto types.", 'Cipher c = Cipher.getInstance("AES/CTR/NoPadding");\nc.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(counter));\noutput.write(c.doFinal(buffer));'),
        ],
        "javascript": [
            ("crypto is node:crypto; authTag arrived separately from the payload.", 'const box = crypto.createDecipheriv("aes-256-gcm", key, iv);\nbox.setAuthTag(authTag);\nconst original = Buffer.concat([box.update(sealed), box.final()]);'),
            ("privateDecrypt is from node:crypto; recipientKey is an RSA private key.", 'const original = privateDecrypt(recipientKey, sealed);'),
            ("CryptoJS is crypto-js; token was produced with the matching passphrase.", 'const words = CryptoJS.AES.decrypt(token, passphrase);\nconst text = words.toString(CryptoJS.enc.Utf8);'),
            ("crypto is Node's crypto module; authentication tag was received with the packet.", 'const box = crypto.createDecipheriv("chacha20-poly1305", secret, nonce, { authTagLength: 16 });\nbox.setAuthTag(tag);\nconst output = Buffer.concat([box.update(packet), box.final()]);'),
        ],
        "typescript": [
            ("webcrypto is imported from node:crypto; aesKey is a CryptoKey.", 'const plaintext: ArrayBuffer = await webcrypto.subtle.decrypt(\n  { name: "AES-GCM", iv }, aesKey, ciphertext);'),
            ("privateDecrypt is imported from node:crypto; recipient is an RSA private KeyObject.", 'const recovered: Buffer = privateDecrypt({ key: recipient }, ciphertext);'),
            ("CryptoJS is crypto-js and token/passphrase are strings.", 'const recovered: string = CryptoJS.AES.decrypt(token, passphrase).toString(CryptoJS.enc.Utf8);'),
            ("createDecipheriv comes from node:crypto; bytes are a received ciphertext chunk.", 'const stream = createDecipheriv("aes-192-cbc", secret, iv);\nconst chunk: Buffer = Buffer.concat([stream.update(bytes), stream.final()]);'),
        ],
    },
    "hashing": {
        "python": [
            ("hashlib is the Python standard library module; payload contains file bytes.", 'digest = hashlib.sha256(payload).hexdigest()'),
            ("hmac and hashlib are standard library modules; secret is the message authentication key.", 'tag = hmac.new(secret, message, hashlib.sha512).digest()'),
            ("bcrypt is the password-processing package; encoded_password contains UTF-8 bytes.", 'stored = bcrypt.hashpw(encoded_password, bcrypt.gensalt())'),
            ("SHA3_256 is imported from Crypto.Hash.", 'state = SHA3_256.new()\nstate.update(chunk_one)\nstate.update(chunk_two)\ndigest = state.hexdigest()'),
        ],
        "java": [
            ("MessageDigest is java.security.MessageDigest; bytes are file contents.", 'MessageDigest md = MessageDigest.getInstance("SHA-256");\nbyte[] digest = md.digest(bytes);'),
            ("Mac and SecretKeySpec are javax.crypto types; secret contains a MAC key.", 'Mac mac = Mac.getInstance("HmacSHA512");\nmac.init(new SecretKeySpec(secret, "HmacSHA512"));\nbyte[] tag = mac.doFinal(payload);'),
            ("BCrypt is the org.mindrot.jbcrypt password library.", 'String stored = BCrypt.hashpw(password, BCrypt.gensalt(12));'),
            ("MessageDigest is java.security.MessageDigest; a legacy checksum format requires MD5.", 'MessageDigest md = MessageDigest.getInstance("MD5");\nmd.update(chunk);\nbyte[] checksum = md.digest();'),
        ],
        "javascript": [
            ("crypto is Node's node:crypto module; payload contains arbitrary bytes.", 'const hash = crypto.createHash("sha256");\nhash.update(payload);\nconst digest = hash.digest("hex");'),
            ("createHmac is from node:crypto; secret is a MAC key.", 'const tag = createHmac("sha512", secret).update(message).digest();'),
            ("bcrypt is the bcrypt package; suppliedPassword is a string.", 'const stored = await bcrypt.hash(suppliedPassword, 12);'),
            ("CryptoJS is crypto-js; text is the input string.", 'const digest = CryptoJS.SHA384(text).toString();'),
        ],
        "typescript": [
            ("webcrypto comes from node:crypto; data is a Uint8Array.", 'const digest: ArrayBuffer = await webcrypto.subtle.digest("SHA-256", data);'),
            ("createHmac is a named import from node:crypto.", 'const tag: string = createHmac("sha256", secret).update(body).digest("base64");'),
            ("bcrypt is the bcrypt package; storedDigest is a stored password hash.", 'const matches: boolean = await bcrypt.compare(candidatePassword, storedDigest);'),
            ("createHash is from node:crypto; chunks is an iterable of buffers.", 'const state = createHash("sha512");\nfor (const chunk of chunks) { state.update(chunk); }\nconst digest: Buffer = state.digest();'),
        ],
    },
    "digital_signature": {
        "python": [
            ("private_key is a cryptography RSA private key; padding and hashes are its primitives.", 'signature = private_key.sign(payload, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())'),
            ("public_key is a cryptography EC public key; ec and hashes come from cryptography.", 'public_key.verify(signature, payload, ec.ECDSA(hashes.SHA256()))'),
            ("signer is a cryptography Ed25519PrivateKey created earlier.", 'signature = signer.sign(document_bytes)'),
            ("DSS and SHA256 are from Crypto.Signature and Crypto.Hash; ecc_key is an ECC private key.", 'signer = DSS.new(ecc_key, "fips-186-3")\nsignature = signer.sign(SHA256.new(message))'),
        ],
        "java": [
            ("Signature is java.security.Signature; privateKey is an RSA PrivateKey.", 'Signature signer = Signature.getInstance("SHA256withRSA");\nsigner.initSign(privateKey);\nsigner.update(payload);\nbyte[] signature = signer.sign();'),
            ("Signature is java.security.Signature; publicKey is an EC PublicKey.", 'Signature verifier = Signature.getInstance("SHA256withECDSA");\nverifier.initVerify(publicKey);\nverifier.update(payload);\nboolean valid = verifier.verify(signature);'),
            ("Signature is java.security.Signature; secret is an Ed25519 PrivateKey.", 'Signature signer = Signature.getInstance("Ed25519");\nsigner.initSign(secret);\nsigner.update(document);\nbyte[] proof = signer.sign();'),
            ("Signature is java.security.Signature; publicKey is an RSA PublicKey.", 'Signature verifier = Signature.getInstance("SHA512withRSA");\nverifier.initVerify(publicKey);\nverifier.update(document);\nif (!verifier.verify(proof)) { throw new SecurityException(); }'),
        ],
        "javascript": [
            ("crypto is node:crypto; privateKey is an RSA private KeyObject.", 'const signature = crypto.sign("sha256", payload, privateKey);'),
            ("crypto is node:crypto; publicKey is an EC public KeyObject.", 'const valid = crypto.verify("sha256", payload, publicKey, signature);'),
            ("sign is imported from node:crypto; signerKey is an Ed25519 private key.", 'const proof = sign(null, document, signerKey);'),
            ("createSign is from node:crypto; pemKey contains an RSA private key.", 'const signer = createSign("RSA-SHA512");\nsigner.update(message);\nconst signature = signer.sign(pemKey);'),
        ],
        "typescript": [
            ("webcrypto is node:crypto.webcrypto; secretKey is an RSA-PSS CryptoKey.", 'const signature: ArrayBuffer = await webcrypto.subtle.sign({ name: "RSA-PSS", saltLength: 32 }, secretKey, payload);'),
            ("webcrypto is node:crypto.webcrypto; publicKey is an ECDSA CryptoKey.", 'const valid: boolean = await webcrypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, publicKey, signature, payload);'),
            ("sign is a named import from node:crypto; key is an Ed25519 private KeyObject.", 'const signature: Buffer = sign(null, bytes, key);'),
            ("createVerify is from node:crypto; publicKey is an RSA key.", 'const checker = createVerify("RSA-SHA256");\nchecker.update(document);\nconst accepted: boolean = checker.verify(publicKey, proof);'),
        ],
    },
    "key_generation": {
        "python": [
            ("RSA is imported from Crypto.PublicKey.", 'key_pair = RSA.generate(2048)'),
            ("ec is cryptography.hazmat.primitives.asymmetric.ec.", 'private_key = ec.generate_private_key(ec.SECP256R1())'),
            ("Ed25519PrivateKey is imported from cryptography.", 'identity = Ed25519PrivateKey.generate()'),
            ("AESGCM is imported from cryptography.hazmat.primitives.ciphers.aead.", 'session_secret = AESGCM.generate_key(bit_length=256)'),
        ],
        "java": [
            ("KeyPairGenerator is java.security.KeyPairGenerator.", 'KeyPairGenerator factory = KeyPairGenerator.getInstance("RSA");\nfactory.initialize(3072);\nKeyPair pair = factory.generateKeyPair();'),
            ("KeyPairGenerator and ECGenParameterSpec are Java security classes.", 'KeyPairGenerator factory = KeyPairGenerator.getInstance("EC");\nfactory.initialize(new ECGenParameterSpec("secp256r1"));\nKeyPair identity = factory.generateKeyPair();'),
            ("KeyPairGenerator is java.security.KeyPairGenerator.", 'KeyPair pair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();'),
            ("KeyGenerator is javax.crypto.KeyGenerator.", 'KeyGenerator factory = KeyGenerator.getInstance("AES");\nfactory.init(256);\nSecretKey sessionKey = factory.generateKey();'),
        ],
        "javascript": [
            ("crypto is Node's crypto module.", 'const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });'),
            ("generateKeyPairSync is imported from node:crypto.", 'const pair = generateKeyPairSync("ec", { namedCurve: "prime256v1" });'),
            ("crypto is Node's crypto module.", 'const identity = crypto.generateKeyPairSync("ed25519");'),
            ("generateKeySync is imported from node:crypto.", 'const sessionKey = generateKeySync("aes", { length: 256 });'),
        ],
        "typescript": [
            ("webcrypto is imported from node:crypto; the result will be a CryptoKeyPair.", 'const pair = await webcrypto.subtle.generateKey({ name: "RSA-PSS", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, false, ["sign", "verify"]);'),
            ("webcrypto is imported from node:crypto.", 'const pair = await webcrypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-384" }, false, ["sign", "verify"]);'),
            ("generateKeyPairSync is a named import from node:crypto.", 'const identity = generateKeyPairSync("ed25519");'),
            ("webcrypto is imported from node:crypto; key will be a CryptoKey.", 'const key = await webcrypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);'),
        ],
    },
    "key_exchange": {
        "python": [
            ("local_key is a cryptography EC private key; peer_key is an EC public key.", 'shared_secret = local_key.exchange(ec.ECDH(), peer_key)'),
            ("local_key is a cryptography X25519PrivateKey and remote_key is an X25519PublicKey.", 'shared = local_key.exchange(remote_key)'),
            ("local_key is a cryptography X448PrivateKey and remote_key is an X448PublicKey.", 'material = local_key.exchange(remote_key)'),
            ("private_key is a cryptography DHPrivateKey; peer_public is a DHPublicKey.", 'shared_bytes = private_key.exchange(peer_public)'),
        ],
        "java": [
            ("KeyAgreement is javax.crypto.KeyAgreement; local and peer are EC keys.", 'KeyAgreement agreement = KeyAgreement.getInstance("ECDH");\nagreement.init(local);\nagreement.doPhase(peer, true);\nbyte[] shared = agreement.generateSecret();'),
            ("KeyAgreement is javax.crypto.KeyAgreement; local and peer are X25519 keys.", 'KeyAgreement agreement = KeyAgreement.getInstance("X25519");\nagreement.init(local);\nagreement.doPhase(peer, true);\nbyte[] secret = agreement.generateSecret();'),
            ("KeyAgreement is javax.crypto.KeyAgreement; local and peer are X448 keys.", 'KeyAgreement session = KeyAgreement.getInstance("X448");\nsession.init(local);\nsession.doPhase(peer, true);\nbyte[] material = session.generateSecret();'),
            ("KeyAgreement is javax.crypto.KeyAgreement; privateKey and peerKey are DH keys.", 'KeyAgreement session = KeyAgreement.getInstance("DiffieHellman");\nsession.init(privateKey);\nsession.doPhase(peerKey, true);\nbyte[] shared = session.generateSecret();'),
        ],
        "javascript": [
            ("ecdh is a Node ECDH instance with its private key already set; peerPublic is the remote public key.", 'const secret = ecdh.computeSecret(peerPublic);'),
            ("diffieHellman is imported from node:crypto; privateKey/publicKey are X25519 KeyObjects.", 'const shared = diffieHellman({ privateKey: localPrivate, publicKey: peerPublic });'),
            ("crypto is node:crypto; local and remote are X448 KeyObjects.", 'const material = crypto.diffieHellman({ privateKey: local, publicKey: remote });'),
            ("session is a Node DiffieHellman object with a local private key already generated.", 'const shared = session.computeSecret(remotePublicBytes);'),
        ],
        "typescript": [
            ("webcrypto is node:crypto.webcrypto; secret/publicKey are ECDH CryptoKeys.", 'const shared = await webcrypto.subtle.deriveBits({ name: "ECDH", public: publicKey }, secret, 256);'),
            ("diffieHellman is from node:crypto; local and peer are X25519 KeyObjects.", 'const shared: Buffer = diffieHellman({ privateKey: local, publicKey: peer });'),
            ("diffieHellman is from node:crypto; myKey and theirKey are X448 KeyObjects.", 'const material: Buffer = diffieHellman({ privateKey: myKey, publicKey: theirKey });'),
            ("handshake is a Node DiffieHellman instance; remote contains public key bytes.", 'const secret: Buffer = handshake.computeSecret(remote);'),
        ],
    },
    "tls_certificate": {
        "python": [
            ("ssl is the Python standard library module; pem paths refer to local files.", 'context = ssl.create_default_context()\ncontext.load_verify_locations(cafile="roots.pem")'),
            ("x509 is imported from cryptography; pem_bytes contains a public certificate.", 'certificate = x509.load_pem_x509_certificate(pem_bytes)\nissuer = certificate.issuer'),
            ("x509 is imported from cryptography; data contains a DER certificate.", 'certificate = x509.load_der_x509_certificate(data)\nexpires = certificate.not_valid_after_utc'),
            ("ctx is an ssl.SSLContext and sock is a connected socket.", 'channel = ctx.wrap_socket(sock, server_hostname="service.example")\npeer = channel.getpeercert()'),
        ],
        "java": [
            ("SSLContext is javax.net.ssl.SSLContext; trusted contains TrustManager instances.", 'SSLContext context = SSLContext.getInstance("TLSv1.3");\ncontext.init(null, trusted, null);'),
            ("CertificateFactory is java.security.cert.CertificateFactory; input contains PEM bytes.", 'CertificateFactory factory = CertificateFactory.getInstance("X.509");\nX509Certificate cert = (X509Certificate) factory.generateCertificate(input);'),
            ("cert is a java.security.cert.X509Certificate already loaded from DER.", 'String issuer = cert.getIssuerX500Principal().getName();\nDate expiration = cert.getNotAfter();'),
            ("socket is a javax.net.ssl.SSLSocket connected to the remote endpoint.", 'socket.startHandshake();\nCertificate[] peer = socket.getSession().getPeerCertificates();'),
        ],
        "javascript": [
            ("tls is Node's node:tls module; roots contains CA certificate PEM data.", 'const context = tls.createSecureContext({ ca: roots, minVersion: "TLSv1.2" });'),
            ("X509Certificate comes from node:crypto; pem contains a public certificate.", 'const cert = new X509Certificate(pem);\nconst issuer = cert.issuer;'),
            ("X509Certificate comes from node:crypto; derBuffer contains a DER certificate.", 'const cert = new X509Certificate(derBuffer);\nconst expires = cert.validTo;'),
            ("tls is imported from node:tls; normal server certificate verification is enabled.", 'const socket = tls.connect({ host: "service.example", port: 443, servername: "service.example" });'),
        ],
        "typescript": [
            ("createSecureContext is from node:tls; rootCertificates contains CA PEM strings.", 'const context = createSecureContext({ ca: rootCertificates, minVersion: "TLSv1.3" });'),
            ("X509Certificate is from node:crypto; pem is a string containing a public certificate.", 'const certificate = new X509Certificate(pem);\nconst subject: string = certificate.subject;'),
            ("X509Certificate is from node:crypto; der is a Buffer containing one certificate.", 'const certificate = new X509Certificate(der);\nconst expiry: string = certificate.validTo;'),
            ("channel is a node:tls TLSSocket whose handshake has completed.", 'const peer = channel.getPeerCertificate();\nconst issuer = peer.issuer;'),
        ],
    },
    "crypto_wrapper": {
        "python": [
            ("secure_provider is an application's opaque security adapter; its implementation is not available.", 'proof = secure_provider.sign(payload)'),
            ("crypto_manager is an internal data-protection facade; its implementation and mechanism are unknown.", 'protected = crypto_manager.protect(data)'),
            ("key_service is a remote security-service adapter; create has no visible implementation.", 'identity = key_service.create()'),
            ("vault is an internal record-protection client; the underlying operations are not shown.", 'stored = vault.encrypt_record(customer_record)'),
        ],
        "java": [
            ("secureProvider is an opaque application security adapter with no available implementation.", 'byte[] proof = secureProvider.sign(payload);'),
            ("cryptoManager is an internal data-protection facade; no algorithm contract is supplied.", 'byte[] protectedData = cryptoManager.protect(data);'),
            ("keyService is a proprietary security-service adapter; create has no visible implementation.", 'Object identity = keyService.create();'),
            ("vault is an application's record-protection service; its implementation is not shown.", 'Object stored = vault.encryptRecord(customerRecord);'),
        ],
        "javascript": [
            ("secure_provider is an opaque security SDK adapter; no algorithm or library is identified.", 'const proof = await secure_provider.sign(payload);'),
            ("crypto_manager is an internal data-protection client whose implementation is absent.", 'const protectedData = crypto_manager.protect(data);'),
            ("key_service is a proprietary security-service facade; create's implementation is absent.", 'const identity = await key_service.create();'),
            ("vault is a record-protection adapter; no underlying mechanism is specified.", 'const stored = await vault.encrypt_record(record);'),
        ],
        "typescript": [
            ("secureProvider is a proprietary security adapter; its implementation is unavailable.", 'const proof: Uint8Array = await secureProvider.sign(payload);'),
            ("cryptoManager is an opaque data-protection SDK without an algorithm contract.", 'const protectedData: Uint8Array = cryptoManager.protect(data);'),
            ("keyService is a security-service facade, not a standard crypto API; implementation is unknown.", 'const identity: unknown = await keyService.create();'),
            ("vault is an internal record-protection adapter; the underlying operation is unestablished.", 'const stored: unknown = await vault.encryptRecord(record);'),
        ],
    },
    "non_crypto": {
        "python": [
            ("user.sign_form records acceptance of a web form with a database boolean, without a digital signing API.", 'user.sign_form()\nsign = "+"'),
            ("record.id is a database identifier; key names a lookup column.", 'database_key = record.id\nkey = "customer_id"'),
            ("hash_table is an ordinary in-memory associative container.", 'hash_table.insert(customer_id, profile)'),
            ("secure_filename is werkzeug.utils.secure_filename; it sanitizes upload names.", 'name = secure_filename(upload.filename)'),
            ("message is user-interface text; the comment is documentation only.", 'message = "RSA documentation"\n# AES and SHA256 are mentioned in a help article.'),
        ],
        "java": [
            ("signForm sets a form-accepted flag; sign is a mathematical operator string.", 'user.signForm();\nString sign = "+";'),
            ("record.id is a database row identifier and key is a column name.", 'long databaseKey = record.id;\nString key = "customer_id";'),
            ("hashTable is a java.util.HashMap and the result is an object bucket hash.", 'hashTable.put(customerId, profile);\nint bucket = profile.hashCode();'),
            ("secureFilename strips directory components and unsafe characters; it performs no cryptographic operations.", 'String safe = secureFilename(upload.getName());'),
            ("message is help text, not an API call.", 'String message = "RSA documentation";\n// TLS and AES are glossary terms here.'),
        ],
        "javascript": [
            ("sign_form stores a checkbox value; sign selects a math operator.", 'user.sign_form();\nconst sign = "+";'),
            ("record.id is a primary key from a database; key selects a property.", 'const database_key = record.id;\nconst key = "customer_id";'),
            ("hash_table is an application map storing profiles by customer ID.", 'hash_table.insert(customerId, profile);'),
            ("secure_filename is a filename-normalization helper, not a crypto function.", 'const safeName = secure_filename(upload.name);'),
            ("message and comment are interface copy, not executable crypto behavior.", 'const message = "RSA documentation";\n// crypto.createHash("sha256") appears in the tutorial.'),
        ],
        "typescript": [
            ("signForm records consent in a form service; sign is a display string.", 'user.signForm();\nconst sign: string = "+";'),
            ("databaseKey is a row ID and key is a typed field name.", 'const databaseKey: number = record.id;\nconst key: string = "customer_id";'),
            ("hashTable is an ordinary Map<string, Profile>, not a digest engine.", 'hashTable.set(customerId, profile);'),
            ("secureFilename is a path sanitization helper; it removes traversal components.", 'const safeName: string = secureFilename(upload.name);'),
            ("message is a string literal used in documentation.", 'const message: string = "RSA documentation";\n// privateKey.sign(payload) is an example printed in help.'),
        ],
    },
}

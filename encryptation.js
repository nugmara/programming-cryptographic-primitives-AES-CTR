async function deriveKeyFromPassword(password) {
    const encoder = new TextEncoder();
    const encodePassword = encoder.encode(password);
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iterations = 100000;
    const keyLength = 256;

    const key = await crypto.subtle.importKey(
        'raw',
        encodePassword,
        { name: "PBKDF2" },
        false,
        ["deriveKey"]
    )

    return await crypto.subtle.deriveKey(
       {
        name: "PBKDF2",
        salt: salt,
        iterations: iterations,
        hash: { name: "SHA-256" }
       },
       key,
       { name: "AES-CTR", length: keyLength },
       false,
       ["encrypt", "descrypt"]
    )
}

// AES encryption
async function encryptMessage(message, password) {
    const encodedMessage = new TextEncoder().encode(message);
    const encryptedData = await crypto.subtle.encrypt(
        { 
            name: "AES-CTR",
            counter: new Uint8Array(16),
            length: 128
        },
        password,
        encodedMessage
    )
    return encryptedData;
}

// AES decryption
async function decryptMessage(encryptedData, password) {
    const decryptedData = await crypto.subtle.decrypt(
        {
            name: "AES-CTR",
            counter: new Uint8Array(16),
            length: 128
        },
        password,
        encryptedData
    )
    const decodedMessage = new TextDecoder().decode(decryptedData)
    return decodedMessage;
}

function generateRandomPassword(length) {
    const charset =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let password = "";
    for (let i = 0; i < length; i++) {
      const randomIndex = Math.floor(Math.random() * charset.length);
      password += charset[randomIndex];
    }
    return password;
  }

  document
    .getElementById("generateButton")
    .addEventListener("click", () => {
      const passwordInput = document.getElementById("password");
      const randomPassword = generateRandomPassword(16); // Generar una contraseña de 16 caracteres
      passwordInput.value = randomPassword;
    });
  const base64ToUInt8Array = (b64) =>
    Uint8Array.from(window.atob(b64), (c) => c.charCodeAt(0));
  const textToUInt8Array = (s) => new TextEncoder().encode(s);
  const Unt8ArrayToString = (u8) => String.fromCharCode.apply(null, u8);
  const UInt8ArrayToBase64 = (u8) => window.btoa(UInt8ArrayToString(u8));
  async function encryptMessage(message, password) {
    const key = await deriveKeyFromPassword(
      password,
      "HT24EFLxzRYATTG4PwMstxuIc6cnfnr4VjIeSJc9SMQ=",
      100000,
      256,
      "SHA-256"
    );

    const iv = window.crypto.getRandomValues(new Uint8Array(16));
    const ciphertext = new Uint8Array(
      await window.crypto.subtle.encrypt(
        {
          name: "AES-CTR",
          counter: iv,
          length: 128,
        },
        key,
        textToUInt8Array(message)
      )
    );

    const encryptedData = new Uint8Array(iv.length + ciphertext.length);
    encryptedData.set(iv);
    encryptedData.set(ciphertext, iv.length);

    return encryptedData;
  }
  async function decryptMessageFromBinary(encryptedData, password) {
    const key = await deriveKeyFromPassword(
      password,
      "HT24EFLxzRYATTG4PwMstxuIc6cnfnr4VjIeSJc9SMQ=",
      100000,
      256,
      "SHA-256"
    );

    const iv = encryptedData.slice(0, 16);
    const ciphertext = encryptedData.slice(16);
    const decryptedBuffer = await window.crypto.subtle.decrypt(
      {
        name: "AES-CTR",
        counter: iv,
        length: 128,
      },
      key,
      ciphertext
    );

    const decryptedMessage = new TextDecoder().decode(decryptedBuffer);
    return decryptedMessage;
  }

  async function deriveKeyFromPassword(
    password,
    salt,
    iterations,
    keyLength,
    hash
  ) {
    const encoder = new TextEncoder();
    let keyMaterial = await crypto.subtle.importKey(
      "raw",
      encoder.encode(password),
      { name: "PBKDF2" },
      false,
      ["deriveKey"]
    );
    return await crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: encoder.encode(salt),
        iterations: iterations,
        hash: hash,
      },
      keyMaterial,
      { name: "AES-CTR", length: keyLength },
      false,
      ["encrypt", "decrypt"]
    );
  }

  // Uso: genera una contraseña aleatoria de 16 caracteres
  const randomPassword = generateRandomPassword(16);
  console.log("Contraseña aleatoria:", randomPassword);

  document.addEventListener("DOMContentLoaded", async () => {
    const encryptButton = document.getElementById("encryptButton");
    // const decryptButton = document.getElementById("decryptButton");

    encryptButton.addEventListener("click", async () => {
      const message = document.getElementById("encryptMessage").value;
      const password = document.getElementById("encryptPassword").value;

      try {
        const encryptedData = await encryptMessage(message, password);
        console.log("Encrypted Data:", encryptedData);
        const blob = new Blob([encryptedData]);
        saveAs(blob, "encrypted_message.bin");
        document.getElementById("encryptedOutput").innerText =
          "Message encrypted and saved as 'encrypted_message.bin'";
      } catch (error) {
        console.error("Encryption error:", error);
        document.getElementById("encryptedOutput").innerText =
          "Encryption failed. Please check your input.";
      }
    });
    document
      .getElementById("fileInput")
      .addEventListener("change", async (event) => {
        const file = event.target.files[0];
        const reader = new FileReader();

        reader.onload = async () => {
          const encryptedData = new Uint8Array(reader.result);
          const password = prompt("Enter password for decryption:");

          try {
            const decryptedMessage = await decryptMessageFromBinary(
              encryptedData,
              password
            );
            document.getElementById(
              "decryptedOutput"
            ).innerText = `Decrypted Message: ${decryptedMessage}`;
          } catch (error) {
            console.error("Decryption error:", error);
            document.getElementById("decryptedOutput").innerText =
              "Decryption failed. Please check your password.";
          }
        };

        reader.readAsArrayBuffer(file);
      });
  });

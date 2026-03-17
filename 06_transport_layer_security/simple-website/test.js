const fs = require('fs');
const { subtle } = require('crypto').webcrypto;

async function importPublicKey() {
    try {
        let response = await fetch("http://192.168.3.2:5000/pk");
        
        if (!response.ok) {
            throw new Error(`HTTP error! Status: ${response.status}`);
        }

        let keyText = await response.text();
        console.log("Fetched Public Key:", keyText); // ✅ Debugging output

        return crypto.subtle.importKey(
            "spki", // or "pkcs8" if it's a private key
            pemToArrayBuffer(keyText),
            { name: "RSA-OAEP", hash: "SHA-256" },
            true,
            ["encrypt"]
        );

    } catch (error) {
        console.error("Failed to import public key:", error);
    }
}

function pemToArrayBuffer(pem) {
    // Remove the PEM header/footer
    let b64Lines = pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
    
    // Convert base64 to a binary string
    let byteString = atob(b64Lines);
    
    // Convert binary string to Uint8Array
    let arrayBuffer = new Uint8Array(byteString.length);
    for (let i = 0; i < byteString.length; i++) {
        arrayBuffer[i] = byteString.charCodeAt(i);
    }
    
    return arrayBuffer.buffer;
}


// Run the test
importPublicKey();


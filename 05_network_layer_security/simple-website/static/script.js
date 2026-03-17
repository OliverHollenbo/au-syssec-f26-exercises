async function fetchAndImportPublicKey(url) {
    try {
        const response = await fetch(url);
        if (!response.ok) throw new Error("Failed to fetch public key");
        const pemKey = await response.text();
        return await importPublicKey(pemKey);
    } catch (error) {
        console.error("Error fetching/importing public key:", error);
    }
}

function pemToArrayBuffer(pem) {
    const base64String = pem.replace(/-----BEGIN PUBLIC KEY-----/, "")
                            .replace(/-----END PUBLIC KEY-----/, "")
                            .replace(/\s+/g, "");
    const binaryString = atob(base64String);
    const arrayBuffer = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
        arrayBuffer[i] = binaryString.charCodeAt(i);
    }
    return arrayBuffer.buffer;
}

async function importPublicKey(pemKey) {
    const spkiBuffer = pemToArrayBuffer(pemKey);
    return await window.crypto.subtle.importKey(
        "spki",
        spkiBuffer,
        { name: "RSA-OAEP", hash: "SHA-256" },
        true,
        ["encrypt"]
    );
}

// Convert Uint8Array to Hex String
function uint8ArrayToHex(uint8Array) {
    return Array.from(uint8Array)
        .map(byte => byte.toString(16).padStart(2, "0"))
        .join("");
}

async function encryptMessage(message, publicKey) {
    const encoder = new TextEncoder();
    const encryptedData = await window.crypto.subtle.encrypt(
        { name: "RSA-OAEP" },
        publicKey,
        encoder.encode(message)
    );
    return uint8ArrayToHex(new Uint8Array(encryptedData)); // Convert to Hex
}

document.querySelector("form").addEventListener("submit", async function(event) {
    event.preventDefault(); // Stop default form submission

    let formData = new FormData(this);
    let response = await fetch("/upload_secrets", {
        method: "POST",
        body: formData
    });

    // Force browser to navigate if Flask redirects
    if (response.redirected) {
        window.location.href = "/thanks";
    } else {
        let result = await response.text();
        document.body.innerHTML = result;  // Render response manually (fallback)
    }
});

async function handleFormSubmit(event) {
    event.preventDefault(); // Prevent normal form submission

    const message = document.getElementById("secrets").value;
    if (!message) {
        alert("Please enter a message.");
        return;
    }

    const keyUrl = `https://${window.location.host}/pk`; // Fetch key from the same domain
    const publicKey = await fetchAndImportPublicKey(keyUrl);

    const encryptedMessage = await encryptMessage(message, publicKey);
    console.log("Encrypted Message:", encryptedMessage);

    // Send encrypted data to server
    const response = await fetch("/upload_secrets/", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ encrypted: encryptedMessage })
    });

    if (response.ok) {
        alert("Message sent securely!");
    } else {
        alert("Failed to send the message.");
    }
}

// Attach event listener when the DOM is loaded
document.addEventListener("DOMContentLoaded", () => {
    document.getElementById("messageForm").addEventListener("submit", handleFormSubmit);
});

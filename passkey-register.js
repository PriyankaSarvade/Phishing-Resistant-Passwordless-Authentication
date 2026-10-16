
import { startRegistration } from "https://esm.sh/@simplewebauthn/browser";

const registerButton = document.getElementById("registerPasskey");

if (registerButton) {
    registerButton.addEventListener("click", async () => {
        const email = document.getElementById("username")?.value
            .trim()
            .toLowerCase();

        if (!email) {
            alert("Please enter your registered email first.");
            return;
        }

        try {
            registerButton.disabled = true;

            const optionsResponse = await fetch("http://localhost:3000/api/register/options", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ email })
            });

            const options = await optionsResponse.json();

            if (!optionsResponse.ok) {
                throw new Error(options.error || "Could not start registration.");
            }

            const credential = await startRegistration({
                optionsJSON: options
            });

            const verifyResponse = await fetch("http://localhost:3000/api/register/verify", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    email,
                    response: credential
                })
            });

            const result = await verifyResponse.json();

            if (!verifyResponse.ok) {
                throw new Error(result.error || "Passkey registration failed.");
            }

            alert("Passkey registered successfully!");
        } catch (error) {
            alert(error.message || "Registration cancelled or failed.");
        } finally {
            registerButton.disabled = false;
        }
    });
}

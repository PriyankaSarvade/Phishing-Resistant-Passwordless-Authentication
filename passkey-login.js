
import { startAuthentication } from "https://esm.sh/@simplewebauthn/browser";

const loginButton = document.getElementById("passkeyLogin");

if (loginButton) {
    loginButton.addEventListener("click", async (event) => {
        event.preventDefault();

        const email = document.getElementById("username")?.value
            .trim()
            .toLowerCase();

        if (!email) {
            alert("Please enter your registered email first.");
            return;
        }

        try {
            loginButton.disabled = true;

            // Step 1: Ask backend for login options
            const optionsResponse = await fetch("/api/login/options", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ email })
            });

            const options = await optionsResponse.json();

            if (!optionsResponse.ok) {
                throw new Error(options.error || "Could not start login.");
            }

            // Step 2: Ask device to verify the passkey
            const credential = await startAuthentication({
                optionsJSON: options
            });

            // Step 3: Send the passkey response to backend
            const verifyResponse = await fetch("/api/login/verify", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    email,
                    response: credential
                })
            });

            const result = await verifyResponse.json();

            if (!verifyResponse.ok) {
                throw new Error(result.error || "Login failed.");
            }

            alert("Passkey verified successfully!");

            window.location.href = result.redirect;
        } catch (error) {
            alert(error.message || "Passkey login failed.");
        } finally {
            loginButton.disabled = false;
        }
    });
}

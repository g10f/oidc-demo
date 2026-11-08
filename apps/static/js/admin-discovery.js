// "Load from discovery document" below the issuer in the admin of an identity provider: the server loads
// <issuer>/.well-known/openid-configuration and checks it (relying_party/admin.py, discovery_view). This script
// replaces the endpoints in the form with the values of the document. Nothing is saved until you save.
document.addEventListener('DOMContentLoaded', () => {
    'use strict';
    const button = document.getElementById('load-discovery');
    if (!button) {
        return;
    }
    const status = document.getElementById('discovery-status');

    button.addEventListener('click', async () => {
        const verifyTls = document.getElementById('id_verify_tls');
        const query = new URLSearchParams({
            issuer: document.getElementById('id_issuer').value.trim(),
            verify_tls: verifyTls && !verifyTls.checked ? 'false' : 'true',
        });
        status.textContent = 'Loading …';
        let data;
        try {
            const response = await fetch(`${button.dataset.url}?${query}`, {credentials: 'same-origin'});
            data = await response.json();
        } catch (e) {
            data = {error: 'The site did not answer.'};
        }
        if (data.error) {
            status.textContent = data.error;
            return;
        }
        for (const [field, value] of Object.entries(data.fields)) {
            const input = document.getElementById(`id_${field}`);
            if (input && input.type === 'checkbox') {
                input.checked = value;
            } else if (input) {
                input.value = value;
            }
        }
        status.textContent = 'Loaded. Check the fields and save.';
    });
});

// Device flow (RFC 8628): asks this site every few seconds whether the login on the other device is finished.
// The site sends the token request to the identity provider, at most once per interval.
(() => {
    'use strict';
    const card = document.getElementById('device');
    const status = document.getElementById('device-status');

    async function poll() {
        let result;
        try {
            const response = await fetch(card.dataset.pollUrl, {
                method: 'POST',
                headers: {'X-CSRFToken': card.dataset.csrfToken},
            });
            if (response.ok) {
                result = await response.json();
            } else {
                // e.g. 403 when the session has ended: asking again would not help
                result = {status: 'error', description: `The site answered with HTTP status ${response.status}.`};
            }
        } catch (e) {
            // The network is gone for a moment, the next poll tries again.
            result = {status: 'pending', interval: Number(card.dataset.interval)};
        }
        if (result.status === 'done') {
            window.location.href = result.next;
        } else if (result.status === 'pending') {
            setTimeout(poll, result.interval * 1000);
        } else {
            status.textContent = result.description;
            status.className = 'text-danger';
        }
    }

    setTimeout(poll, Number(card.dataset.interval) * 1000);
})();

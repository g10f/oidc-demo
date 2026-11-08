// Buttons with data-copy put that value into the clipboard (used for the tokens).
(() => {
    'use strict';
    document.addEventListener('click', async (event) => {
        const button = event.target.closest('[data-copy]');
        if (!button) {
            return;
        }
        event.preventDefault();  // the button sits in the summary of a details element, a click must not fold it
        const label = button.innerHTML;
        try {
            await navigator.clipboard.writeText(button.dataset.copy);
            button.innerHTML = '<i class="bi bi-clipboard-check"></i> Copied';
        } catch (e) {
            // The clipboard needs https or localhost, and the permission of the browser.
            button.innerHTML = '<i class="bi bi-x-circle"></i> Not possible';
        }
        setTimeout(() => { button.innerHTML = label; }, 2000);
    });
})();

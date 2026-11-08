// Implicit flow: the identity provider returns the tokens in the fragment of the url, which never reaches the
// server. This script removes them from the address bar and posts them to this site, which checks them.
(() => {
    'use strict';
    if (!window.location.hash) {
        return;
    }
    const params = new URLSearchParams(window.location.hash.substring(1));
    // The tokens must not stay in the address bar and the browser history.
    history.replaceState(null, '', window.location.pathname + window.location.search);
    if (!params.has('state')) {
        return;
    }
    const form = document.getElementById('implicit-response');
    for (const [name, value] of params) {
        const input = document.createElement('input');
        input.type = 'hidden';
        input.name = name;
        input.value = value;
        form.appendChild(input);
    }
    form.submit();
})();

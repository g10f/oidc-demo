// Session Management 1.0, the RP iframe (section 3.1): every few seconds it asks the OP iframe of the identity
// provider whether the session there has changed. On "changed" the page starts a silent login (prompt=none):
// it either gets a new session_state or, if the user has logged out at the identity provider, logs out here too.
// A "changed" right after a silent login means the OP iframe can't read its state (third-party cookies blocked):
// then the checks stop for this login.
(() => {
    'use strict';
    const data = document.body.dataset;
    const message = data.clientId + ' ' + data.sessionState;
    const op = window.parent.document.getElementById('op');
    let timer;

    function checkSession() {
        op.contentWindow.postMessage(message, data.opOrigin);
    }

    window.addEventListener('message', (event) => {
        if (event.origin !== data.opOrigin) {
            return;  // only the identity provider may answer
        }
        if (event.data === 'changed') {
            clearInterval(timer);
            if (data.recentlyChecked === 'true') {
                // The silent login just confirmed the session, so the OP iframe can't read its own state, usually
                // because the browser blocks the cookie of the identity provider in this iframe of another site.
                console.warn('The check_session_iframe answers "changed" right after a silent login, ' +
                    'probably it can not read its cookie (third-party cookies). The session checks are stopped.');
                // Tell the server, so the next pages don't start the checks again.
                fetch(data.stopUrl, {method: 'POST', headers: {'X-CSRFToken': data.csrfToken}});
                return;
            }
            const next = window.parent.location.pathname + window.parent.location.search;
            window.parent.location.href = data.checkUrl + '&next=' + encodeURIComponent(next);
        } else if (event.data === 'error') {
            clearInterval(timer);
            console.warn('The check_session_iframe answered with "error".');
        }
    });

    timer = setInterval(checkSession, 10000);
})();

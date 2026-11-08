// The upload button of the picture is only active when an image is chosen that the identity provider accepts.
// Without JavaScript the button stays active, the server checks the same.
(() => {
    'use strict';
    const form = document.getElementById('picture-form');
    const file = document.getElementById('picture-file');
    const upload = document.getElementById('picture-upload');
    const error = document.getElementById('picture-error');
    const maxSize = Number(form.dataset.maxSize) || 0;

    function update() {
        const chosen = file.files[0];
        const tooLarge = Boolean(chosen && maxSize && chosen.size > maxSize);
        upload.disabled = !chosen || tooLarge;
        error.hidden = !tooLarge;
        error.textContent = tooLarge ? form.dataset.tooLarge : '';
    }

    file.addEventListener('change', update);
    update();
})();

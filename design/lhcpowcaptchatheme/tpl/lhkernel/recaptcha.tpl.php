<?php $recaptchaData = erLhcoreClassPowCaptcha::getRecaptchaSettings(); ?>
<?php $captchaAction = isset($captchaAction) ? $captchaAction : 'login_action'; ?>

<?php if ((int)$recaptchaData['enabled'] === 1 && $recaptchaData['provider'] === 'google') : ?>
    <input type="hidden" name="g-recaptcha" id="recaptcha-content" value="">

    <script src="https://www.google.com/recaptcha/api.js?render=<?php echo htmlspecialchars($recaptchaData['site_key'])?>"></script>
    <script>
        grecaptcha.ready(function() {
            grecaptcha.execute('<?php echo htmlspecialchars($recaptchaData['site_key'])?>', {action: '<?php echo htmlspecialchars($captchaAction)?>'})
                .then(function(token) {
                    $('#recaptcha-content').val(token);
                });
        });
    </script>
<?php elseif ((int)$recaptchaData['enabled'] === 1 && $recaptchaData['provider'] === 'turnstile') : ?>
    <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
    <div class="cf-turnstile mt-2"
         data-sitekey="<?php echo htmlspecialchars($recaptchaData['turnstile_site_key'])?>"
         data-action="<?php echo htmlspecialchars($captchaAction)?>">
    </div>
<?php elseif ((int)$recaptchaData['enabled'] === 1 && $recaptchaData['provider'] === 'pow') : ?>
    <input type="hidden" name="pow_challenge" value="">
    <input type="hidden" name="pow_nonce" value="">

    <style>
        @keyframes pow-spin  { to { transform: rotate(360deg); } }
        @keyframes pow-pop   { 0% { transform: scale(.3); opacity: 0; } 65% { transform: scale(1.25); } 100% { transform: scale(1); opacity: 1; } }
        @keyframes pow-shake { 0%, 100% { transform: translateX(0); } 25% { transform: translateX(-5px); } 75% { transform: translateX(5px); } }
        .pow-spinner { display: inline-block; width: 11px; height: 11px; border: 2px solid currentColor; border-top-color: transparent; border-radius: 50%; animation: pow-spin .7s linear infinite; opacity: .6; vertical-align: middle; flex-shrink: 0; }
    </style>

    <div class="mt-2 small text-muted" data-powcaptcha-status style="display:flex;align-items:center;gap:6px;min-height:1.5em">
        <span data-powcaptcha-icon class="pow-spinner"></span>
        <span data-powcaptcha-msg><?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('user/login','Verifying captcha...');?></span>
    </div>

    <script>
        (function () {
            var form = document.currentScript.closest('form');
            if (!form) {
                return;
            }

            var challengeInput = form.querySelector('input[name="pow_challenge"]');
            var nonceInput = form.querySelector('input[name="pow_nonce"]');
            var statusEl = form.querySelector('[data-powcaptcha-status]');
            var iconEl   = statusEl ? statusEl.querySelector('[data-powcaptcha-icon]') : null;
            var msgEl    = statusEl ? statusEl.querySelector('[data-powcaptcha-msg]')  : null;

            var solvePromise = null;
            var challengeExpiresAt = 0;
            var POW_DIFFICULTY_MIN = 12;
            var POW_DIFFICULTY_MAX = 26;
            var POW_SOLVE_YIELD_CHECK_EVERY = 1000;
            var POW_SOLVE_YIELD_AFTER_MS = 12;

            var MSG_PREPARING  = <?php echo json_encode(erTranslationClassLhTranslation::getInstance()->getTranslation('user/login', 'Verifying captcha...'));?>;
            var MSG_SOLVING    = <?php echo json_encode(erTranslationClassLhTranslation::getInstance()->getTranslation('user/login', 'Solving captcha challenge...'));?>;
            var MSG_VERIFIED   = <?php echo json_encode(erTranslationClassLhTranslation::getInstance()->getTranslation('user/login', 'Captcha verified.'));?>;
            var MSG_SUBMITTING = <?php echo json_encode(erTranslationClassLhTranslation::getInstance()->getTranslation('user/login', 'Captcha verified. Submitting...'));?>;
            var MSG_NO_CRYPTO  = <?php echo json_encode(erTranslationClassLhTranslation::getInstance()->getTranslation('user/login', 'PoW captcha requires a modern browser with cryptography support.'));?>;
            var MSG_FAILED     = <?php echo json_encode(erTranslationClassLhTranslation::getInstance()->getTranslation('user/login', 'Captcha verification failed. Please try again.'));?>;

            function setStatus(message, state) {
                if (!statusEl) {
                    return;
                }
                if (msgEl) {
                    msgEl.textContent = message;
                }
                statusEl.className = 'mt-2 small';
                if (state === 'success') {
                    statusEl.classList.add('text-success');
                    if (iconEl) {
                        iconEl.className = '';
                        iconEl.textContent = '✓';
                        iconEl.style.cssText = 'font-size:1.15em;display:inline-block;flex-shrink:0;animation:pow-pop .35s cubic-bezier(.175,.885,.32,1.275) both';
                    }
                } else if (state === 'error') {
                    statusEl.classList.add('text-danger');
                    if (iconEl) {
                        iconEl.className = '';
                        iconEl.textContent = '✕';
                        iconEl.style.cssText = 'font-size:1.15em;display:inline-block;flex-shrink:0;animation:pow-shake .4s ease-out both';
                    }
                } else {
                    statusEl.classList.add('text-muted');
                    if (iconEl) {
                        iconEl.className = 'pow-spinner';
                        iconEl.textContent = '';
                        iconEl.style.cssText = '';
                    }
                }
            }

            function isSolvedAndFresh() {
                return challengeInput.value !== '' &&
                    nonceInput.value !== '' &&
                    Math.floor(Date.now() / 1000) < challengeExpiresAt - 30;
            }

            function hasLeadingZeroBitsFromBytes(hashBytes, requiredBits) {
                var fullZeroBytes = Math.floor(requiredBits / 8);
                var remainingBits = requiredBits % 8;

                for (var i = 0; i < fullZeroBytes; i++) {
                    if (hashBytes[i] !== 0) {
                        return false;
                    }
                }

                if (remainingBits === 0) {
                    return true;
                }

                var mask = (0xFF << (8 - remainingBits)) & 0xFF;
                return (hashBytes[fullZeroBytes] & mask) === 0;
            }

            var textEncoder = new TextEncoder();

            async function sha256HasLeadingZeroBits(input, requiredBits) {
                var data = textEncoder.encode(input);
                var digest = await crypto.subtle.digest('SHA-256', data);
                return hasLeadingZeroBitsFromBytes(new Uint8Array(digest), requiredBits);
            }

            function getNow() {
                if (window.performance && typeof window.performance.now === 'function') {
                    return window.performance.now();
                }
                return Date.now();
            }

            async function solvePow(challenge, difficulty) {
                var nonce = 0;
                var prefix = challenge + '|';
                var lastYieldAt = getNow();

                while (true) {
                    var candidate = nonce.toString(16);

                    if (await sha256HasLeadingZeroBits(prefix + candidate, difficulty)) {
                        return candidate;
                    }

                    nonce++;

                    if ((nonce % POW_SOLVE_YIELD_CHECK_EVERY) === 0) {
                        var now = getNow();
                        if ((now - lastYieldAt) >= POW_SOLVE_YIELD_AFTER_MS) {
                            await new Promise(function (resolve) { setTimeout(resolve, 0); });
                            lastYieldAt = getNow();
                        }
                    }
                }
            }

            async function fetchAndSolve() {
                challengeInput.value = '';
                nonceInput.value = '';
                challengeExpiresAt = 0;

                setStatus(MSG_PREPARING);

                var response = await fetch('<?php echo erLhcoreClassDesign::baseurl('powcaptcha/challenge')?>/<?php echo rawurlencode($captchaAction)?>', {
                    method: 'GET',
                    credentials: 'same-origin',
                    headers: {'Accept': 'application/json'}
                });

                if (!response.ok) {
                    throw new Error('challenge_request_failed');
                }

                var challengeData = await response.json();
                var difficulty = parseInt(challengeData.difficulty, 10);
                var expiresIn = parseInt(challengeData.expires_in, 10);

                var hasValidChallenge = !!challengeData.challenge;
                var hasValidDifficulty = !isNaN(difficulty) && difficulty >= POW_DIFFICULTY_MIN && difficulty <= POW_DIFFICULTY_MAX;
                var hasValidExpiresIn = !isNaN(expiresIn) && expiresIn > 0;

                if (!hasValidChallenge || !hasValidDifficulty || !hasValidExpiresIn) {
                    throw new Error('challenge_payload_invalid');
                }

                challengeExpiresAt = Math.floor(Date.now() / 1000) + expiresIn;

                setStatus(MSG_SOLVING);

                var nonce = await solvePow(challengeData.challenge, difficulty);

                challengeInput.value = challengeData.challenge;
                nonceInput.value = nonce;

                setStatus(MSG_VERIFIED, 'success');
            }

            if (!window.crypto || !window.crypto.subtle || !window.TextEncoder) {
                setStatus(MSG_NO_CRYPTO, 'error');
            } else {
                solvePromise = fetchAndSolve().catch(function () {
                    setStatus(MSG_FAILED, 'error');
                });
            }

            form.addEventListener('submit', async function (e) {
                // Capture the button that triggered the submit synchronously, before
                // any async work, since document.activeElement may change afterwards.
                var submitBtn = (document.activeElement && document.activeElement.form === form && document.activeElement.type === 'submit')
                    ? document.activeElement
                    : form.querySelector('[type="submit"]');

                if (isSolvedAndFresh()) {
                    // Kick off a fresh solve immediately (after the browser captures the
                    // current form data) so that any retry — e.g. after a wrong password
                    // in an AJAX-mode login — gets a brand-new proof instead of hitting
                    // the server-side replay-detection check.
                    setTimeout(function () {
                        solvePromise = fetchAndSolve().catch(function () {
                            setStatus(MSG_FAILED, 'error');
                        });
                    }, 0);
                    return;
                }

                e.preventDefault();

                if (!window.crypto || !window.crypto.subtle || !window.TextEncoder) {
                    setStatus(MSG_NO_CRYPTO, 'error');
                    return;
                }

                try {
                    // Await the background solve only while the fetched challenge is still fresh
                    if (solvePromise !== null && Math.floor(Date.now() / 1000) < challengeExpiresAt - 30) {
                        await solvePromise;
                    }

                    // If still not solved (background solve failed or challenge expired), solve fresh
                    if (!isSolvedAndFresh()) {
                        solvePromise = fetchAndSolve();
                        await solvePromise;
                    }

                    setStatus(MSG_SUBMITTING, 'success');

                    // form.submit() does not include the active submit button value in the
                    // POST data; add it as a hidden field so the server can identify which
                    // action was triggered (e.g. $_POST['Login']).
                    var hiddenBtn = null;
                    if (submitBtn && submitBtn.name) {
                        hiddenBtn = document.createElement('input');
                        hiddenBtn.type = 'hidden';
                        hiddenBtn.name = submitBtn.name;
                        hiddenBtn.value = submitBtn.value;
                        form.appendChild(hiddenBtn);
                    }
                    form.submit();
                } catch (err) {
                    setStatus(MSG_FAILED, 'error');
                }
            });
        })();
    </script>
<?php endif; ?>

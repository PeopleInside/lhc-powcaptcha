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

    <div class="mt-2 text-muted small" data-powcaptcha-status>
        <?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('user/login','Verifying captcha...');?>
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

            var solvePromise = null;
            var challengeExpiresAt = 0;

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
                statusEl.textContent = message;
                statusEl.className = 'mt-2 small';
                if (state === 'success') {
                    statusEl.classList.add('text-success');
                } else if (state === 'error') {
                    statusEl.classList.add('text-danger');
                } else {
                    statusEl.classList.add('text-muted');
                }
            }

            function isSolvedAndFresh() {
                return challengeInput.value !== '' &&
                    nonceInput.value !== '' &&
                    Math.floor(Date.now() / 1000) < challengeExpiresAt - 30;
            }

            function hasLeadingZeroBits(hexHash, requiredBits) {
                var fullZeroNibbles = Math.floor(requiredBits / 4);
                var remainingBits = requiredBits % 4;

                if (fullZeroNibbles > 0 && hexHash.slice(0, fullZeroNibbles) !== '0'.repeat(fullZeroNibbles)) {
                    return false;
                }

                if (remainingBits === 0) {
                    return true;
                }

                var nibble = parseInt(hexHash.charAt(fullZeroNibbles), 16);
                var threshold = 1 << (4 - remainingBits);
                return nibble < threshold;
            }

            async function sha256Hex(input) {
                var data = new TextEncoder().encode(input);
                var digest = await crypto.subtle.digest('SHA-256', data);
                var bytes = Array.from(new Uint8Array(digest));
                return bytes.map(function (b) { return b.toString(16).padStart(2, '0'); }).join('');
            }

            async function solvePow(challenge, difficulty) {
                var nonce = 0;
                while (true) {
                    var candidate = nonce.toString(16);
                    var digest = await sha256Hex(challenge + '|' + candidate);
                    if (hasLeadingZeroBits(digest, difficulty)) {
                        return candidate;
                    }
                    nonce++;
                    if ((nonce % 50) === 0) {
                        await new Promise(function (resolve) { setTimeout(resolve, 0); });
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
                if (!challengeData.challenge || !challengeData.difficulty) {
                    throw new Error('challenge_payload_invalid');
                }

                challengeExpiresAt = Math.floor(Date.now() / 1000) + parseInt(challengeData.expires_in, 10);

                setStatus(MSG_SOLVING);

                var nonce = await solvePow(challengeData.challenge, parseInt(challengeData.difficulty, 10));

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
                if (isSolvedAndFresh()) {
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
                    form.submit();
                } catch (err) {
                    setStatus(MSG_FAILED, 'error');
                }
            });
        })();
    </script>
<?php endif; ?>

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
        <?php echo erTranslationClassLhTranslation::getInstance()->getTranslation('user/login','PoW captcha is prepared on submit.');?>
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

            var inProgress = false;
            var solvedForCurrentChallenge = false;

            function setStatus(message) {
                if (statusEl) {
                    statusEl.textContent = message;
                }
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

            form.addEventListener('submit', async function (e) {
                if (solvedForCurrentChallenge === true || inProgress === true) {
                    return;
                }

                e.preventDefault();
                inProgress = true;

                if (!window.crypto || !window.crypto.subtle || !window.TextEncoder) {
                    setStatus('PoW captcha requires modern browser cryptography support.');
                    inProgress = false;
                    return;
                }

                try {
                    setStatus('Preparing PoW challenge...');
                    var response = await fetch('<?php echo erLhcoreClassDesign::baseurl('powcaptcha/challenge')?>/<?php echo rawurlencode($captchaAction)?>', {
                        method: 'GET',
                        credentials: 'same-origin',
                        headers: {
                            'Accept': 'application/json'
                        }
                    });

                    if (!response.ok) {
                        throw new Error('challenge_request_failed');
                    }

                    var challengeData = await response.json();
                    if (!challengeData.challenge || !challengeData.difficulty) {
                        throw new Error('challenge_payload_invalid');
                    }

                    setStatus('Solving PoW captcha...');
                    var nonce = await solvePow(challengeData.challenge, parseInt(challengeData.difficulty, 10));

                    challengeInput.value = challengeData.challenge;
                    nonceInput.value = nonce;
                    solvedForCurrentChallenge = true;

                    setStatus('PoW captcha solved. Submitting...');
                    form.submit();
                } catch (err) {
                    setStatus('Failed to solve PoW captcha. Please try again.');
                } finally {
                    inProgress = false;
                }
            });
        })();
    </script>
<?php endif; ?>

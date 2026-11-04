<?php
$t = erTranslationClassLhTranslation::getInstance();
$powJson = JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT;
$powTxt = array(
    'title' => $t->getTranslation('pow/twofactor', 'Two-factor authentication'),
    'intro' => $t->getTranslation('pow/twofactor', 'You are signing in from a new IP address. We sent a 6-digit code to'),
    'label' => $t->getTranslation('pow/twofactor', 'Verification code'),
    'verify' => $t->getTranslation('pow/twofactor', 'Verify'),
    'resend' => $t->getTranslation('pow/twofactor', 'Resend code'),
    'cancel' => $t->getTranslation('pow/twofactor', 'Cancel'),
    'network' => $t->getTranslation('pow/twofactor', 'Network error, please try again.'),
);
?>
<script>
(function () {
    var URL_2FA = <?php echo json_encode(erLhcoreClassDesign::baseurl('powcaptcha/challenge/twofactor'), $powJson) ?>;
    var TOKEN = <?php echo json_encode((string)$pow_2fa_token, $powJson) ?>;
    var LOGIN_URL = <?php echo json_encode(erLhcoreClassDesign::baseurl('user/login'), $powJson) ?>;
    var EMAIL = <?php echo json_encode((string)$pow_2fa_masked, $powJson) ?>;
    var T = <?php echo json_encode($powTxt, $powJson) ?>;

    function build() {
        var ov = document.createElement('div');
        ov.style.cssText = 'position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,.6);z-index:99999;display:flex;align-items:center;justify-content:center;padding:16px;';
        ov.innerHTML =
            '<div role="dialog" aria-modal="true" style="background:#fff;color:#212529;border-radius:10px;max-width:400px;width:100%;padding:24px;box-shadow:0 10px 40px rgba(0,0,0,.4);font-family:inherit;">' +
            '<h4 data-r="title" style="margin:0 0 12px;"></h4>' +
            '<p data-r="intro" style="margin:0 0 14px;"></p>' +
            '<label data-r="label" style="display:block;margin-bottom:4px;font-size:13px;"></label>' +
            '<input data-r="code" type="text" inputmode="numeric" pattern="[0-9]*" maxlength="6" autocomplete="one-time-code" style="width:100%;box-sizing:border-box;font-size:26px;letter-spacing:8px;text-align:center;padding:8px;border:1px solid #adb5bd;border-radius:6px;" />' +
            '<div data-r="msg" style="min-height:22px;margin:8px 0;font-size:13px;"></div>' +
            '<div style="display:flex;gap:8px;flex-wrap:wrap;">' +
            '<button type="button" data-r="verify" class="btn btn-primary btn-sm"></button>' +
            '<button type="button" data-r="resend" class="btn btn-outline-secondary btn-sm"></button>' +
            '<button type="button" data-r="cancel" class="btn btn-link btn-sm" style="margin-left:auto;"></button>' +
            '</div></div>';
        document.body.appendChild(ov);

        function el(n) { return ov.querySelector('[data-r="' + n + '"]'); }
        el('title').textContent = T.title;
        el('intro').textContent = T.intro + ' ' + EMAIL + '.';
        el('label').textContent = T.label;
        el('verify').textContent = T.verify;
        el('resend').textContent = T.resend;
        el('cancel').textContent = T.cancel;

        var input = el('code'), msg = el('msg'), busy = false, dead = false;

        function show(text, bad) {
            msg.textContent = text || '';
            msg.style.color = bad ? '#c53030' : '#2f855a';
        }

        function send(action) {
            if (busy) { return; }
            if (dead) { window.location.href = LOGIN_URL; return; }
            busy = true;
            var fd = new FormData();
            fd.append('pow_2fa_ajax', '1');
            fd.append('token', TOKEN);
            fd.append('do', action);
            fd.append('code', input.value);
            fetch(URL_2FA, {method: 'POST', body: fd, credentials: 'same-origin'})
                .then(function (r) {
                    return r.text().then(function (txt) {
                        try { return JSON.parse(txt); }
                        catch (e) {
                            return {success: false, error: T.network + ' [HTTP ' + r.status + '] ' + txt.replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 140)};
                        }
                    });
                })
                .then(function (d) {
                    busy = false;
                    if (d.success) { window.location.href = d.redirect; return; }
                    if (d.fatal) { dead = true; el('verify').textContent = 'OK'; }
                    show(d.error || d.info || '', !!d.error);
                    if (d.error) { input.value = ''; input.focus(); }
                })
                .catch(function () { busy = false; show(T.network, true); });
        }

        input.addEventListener('input', function () {
            input.value = input.value.replace(/\D/g, '').slice(0, 6);
            if (input.value.length === 6) { send('verify'); }
        });
        input.addEventListener('keydown', function (e) {
            if (e.key === 'Enter') { e.preventDefault(); send('verify'); }
        });
        el('verify').addEventListener('click', function () { send('verify'); });
        el('resend').addEventListener('click', function () { send('resend'); });
        el('cancel').addEventListener('click', function () { ov.parentNode.removeChild(ov); });
        input.focus();
    }

    if (document.body) { build(); } else { document.addEventListener('DOMContentLoaded', build); }
})();
</script>

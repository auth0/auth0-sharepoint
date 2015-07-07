<!DOCTYPE html>
<html lang="en">
<head>
    <title>SharePoint Login</title>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <meta name="apple-mobile-web-app-capable" content="yes" />
    <meta http-equiv="X-UA-Compatible" content="IE=Edge" />
</head>
<body>
    <script src="//ajax.googleapis.com/ajax/libs/jquery/1.10.2/jquery.min.js"></script>
    <script src="//cdn.auth0.com/js/lock-7.6.min.js"></script>
    <script type="text/javascript">
    function getParameterByName(name) {
        name = name.replace(/[\[]/, "\\\[").replace(/[\]]/, "\\\]");
        var regexS = "[\\?&]" + name + "=([^&#]*)";
        var regex = new RegExp(regexS);
        var results = regex.exec(window.location.search);
        if (results == null) return "";
        else return decodeURIComponent(results[1].replace(/\+/g, " "));
    }

    if (!window.location.origin) {
        window.location.origin = window.location.protocol + "//" + window.location.hostname + (window.location.port ? ':' + window.location.port : '');
    }

    var allowWindowsAuth = true;
    var lock = new Auth0Lock('YOUR_CLIENT_ID', 'YOUR_AUTH0_DOMAIN');

    window.onload = function () {
        lock.on('signin submit', function (options, context) {
            if (!options.authParams)
                options.authParams = {};
            options.authParams.login_hint = context.email;
        });
        lock.once('signin ready', function () {
            if (!allowWindowsAuth) {
                return;
            }

            if ($('#a0-lock .a0-onestep .a0-notloggedin .a0-iconlist .a0-zocial.a0-block.a0-windows.windows-auth').length > 0) {
                return;
            }

            var addSocialSeparator = false;
            if ($('#a0-lock .a0-onestep .a0-notloggedin .a0-iconlist .a0-icon').length > 0 || $('#a0-lock .a0-onestep .a0-notloggedin .a0-iconlist .a0-block').length > 0) {
                addSocialSeparator = true;
            }

            var link = $('<a class="a0-zocial a0-block a0-windows windows-auth" href="/_windows/default.aspx?ReturnUrl=' + getParameterByName('ReturnUrl') + '&Source=' + getParameterByName('Source') + '"><span>Login with Windows Auth</span></a>');
            link.appendTo('#a0-lock .a0-onestep .a0-notloggedin .a0-iconlist');
            $('#a0-lock #a0-onestep').css('height', 'auto');
            $('#a0-lock .a0-signin .a0-notloggedin .a0-iconlist').removeClass('a0-hide');

            if (addSocialSeparator) {
                $('#a0-lock .a0-signin .a0-notloggedin .a0-separator').clone().removeClass('a0-hide').show().insertBefore(link);
            }

            if (!$('#a0-lock .a0-onestep .a0-notloggedin .a0-corporate-credentials').hasClass('a0-hide') || !$('#a0-lock .a0-onestep .a0-notloggedin .a0-emailPassword .a0-inputs').hasClass('a0-hide')) {
                $('#a0-lock .a0-signin .a0-notloggedin .a0-collapse-social > .a0-separator').removeClass('a0-hide');
            }
        });
        lock.show({
            callbackURL: location.origin + '/_trust/',
            closable: false,
            authParams: {
                state: getParameterByName('Source'),
                protocol: 'wsfed'
            }
        });
    }
    </script>
</body>
</html>
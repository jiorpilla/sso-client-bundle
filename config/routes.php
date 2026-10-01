<?php

use Symfony\Component\Routing\Loader\Configurator\RoutingConfigurator;

/*
 * Import in your app's config/routes/sso_client.yaml:
 *
 *     sso_client:
 *         resource: '@SsoClientBundle/config/routes.php'
 */
return static function (RoutingConfigurator $routes): void {
    $routes->add('sso_client_login', '/sso/login')
        ->controller('sso_client.controller::login')
        ->methods(['GET']);

    $routes->add('sso_client_callback', '/sso/callback')
        ->controller('sso_client.controller::callback')
        ->methods(['GET']);

    $routes->add('sso_client_logout', '/sso/logout')
        ->controller('sso_client.controller::logout')
        ->methods(['GET', 'POST']);

    $routes->add('sso_client_backchannel_logout', '/sso/backchannel-logout')
        ->controller('sso_client.controller::backchannelLogout')
        ->methods(['POST']);
};

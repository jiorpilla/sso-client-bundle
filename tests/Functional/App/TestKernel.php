<?php

namespace Jiorpilla\SsoClientBundle\Tests\Functional\App;

use Jiorpilla\SsoClientBundle\SsoClientBundle;
use Jiorpilla\SsoClientBundle\Tests\Fixtures\TokenFactory;
use Symfony\Bundle\FrameworkBundle\FrameworkBundle;
use Symfony\Bundle\FrameworkBundle\Kernel\MicroKernelTrait;
use Symfony\Bundle\SecurityBundle\SecurityBundle;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\HttpKernel\Kernel;
use Symfony\Component\Routing\Loader\Configurator\RoutingConfigurator;

/**
 * A minimal app using the bundle the way the README documents.
 */
final class TestKernel extends Kernel
{
    use MicroKernelTrait;

    public function registerBundles(): iterable
    {
        yield new FrameworkBundle();
        yield new SecurityBundle();
        yield new SsoClientBundle();
    }

    public function getProjectDir(): string
    {
        return __DIR__;
    }

    public function getCacheDir(): string
    {
        return sys_get_temp_dir().'/sso-client-bundle-tests/cache';
    }

    public function getLogDir(): string
    {
        return sys_get_temp_dir().'/sso-client-bundle-tests/log';
    }

    protected function configureContainer(ContainerConfigurator $container): void
    {
        $container->extension('framework', [
            'secret' => 'test',
            'test' => true,
            'http_method_override' => false,
            'session' => ['storage_factory_id' => 'session.storage.factory.mock_file'],
            'router' => ['utf8' => true],
            'cache' => ['app' => 'cache.adapter.filesystem', 'directory' => sys_get_temp_dir().'/sso-client-bundle-tests/pools'],
        ]);

        $container->extension('security', [
            'providers' => ['sso' => ['id' => 'sso_client.user_provider']],
            'firewalls' => [
                'api' => [
                    'pattern' => '^/api/',
                    'stateless' => true,
                    'provider' => 'sso',
                    'custom_authenticators' => ['sso_client.bearer_authenticator'],
                ],
                'main' => [
                    'lazy' => true,
                    'provider' => 'sso',
                    'custom_authenticators' => ['sso_client.authenticator'],
                    'entry_point' => 'sso_client.authenticator',
                    'logout' => ['path' => 'sso_client_logout', 'target' => 'home'],
                ],
            ],
            'access_control' => [
                ['path' => '^/sso/', 'roles' => 'PUBLIC_ACCESS'],
                ['path' => '^/$', 'roles' => 'PUBLIC_ACCESS'],
                ['path' => '^/', 'roles' => 'ROLE_USER'],
            ],
        ]);

        $container->extension('sso_client', [
            'issuer' => TokenFactory::ISSUER,
            'client_id' => TokenFactory::CLIENT_ID,
            'client_secret' => 'test-secret',
            'http_client' => 'test.fake_sso_http_client',
        ]);

        $container->services()
            ->set('test.fake_sso_http_client', FakeSsoHttpClient::class)
            ->set(TestController::class)->autowire()->autoconfigure()->tag('controller.service_arguments');
    }

    protected function configureRoutes(RoutingConfigurator $routes): void
    {
        $routes->import('@SsoClientBundle/config/routes.php');
        $routes->import(TestController::class, 'attribute');
    }
}

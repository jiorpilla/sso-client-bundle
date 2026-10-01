<?php

namespace Jiorpilla\SsoClientBundle;

use Jiorpilla\SsoClientBundle\Client\OidcClient;
use Jiorpilla\SsoClientBundle\Controller\SsoController;
use Jiorpilla\SsoClientBundle\Discovery\OidcDiscovery;
use Jiorpilla\SsoClientBundle\EventListener\BackchannelLogoutListener;
use Jiorpilla\SsoClientBundle\EventListener\SsoLogoutListener;
use Jiorpilla\SsoClientBundle\Jwt\JwksProvider;
use Jiorpilla\SsoClientBundle\Jwt\TokenVerifier;
use Jiorpilla\SsoClientBundle\Security\BackchannelLogoutRegistry;
use Jiorpilla\SsoClientBundle\Security\BearerTokenAuthenticator;
use Jiorpilla\SsoClientBundle\Security\OidcAuthenticator;
use Jiorpilla\SsoClientBundle\Security\PendingLoginStore;
use Jiorpilla\SsoClientBundle\Security\SessionUserProvider;
use Jiorpilla\SsoClientBundle\Security\SsoUserProviderInterface;
use Jiorpilla\SsoClientBundle\Token\SsoTokenStorage;
use Symfony\Component\Config\Definition\Configurator\DefinitionConfigurator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\HttpKernel\Bundle\AbstractBundle;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\Security\Http\Event\LogoutEvent;

use function Symfony\Component\DependencyInjection\Loader\Configurator\service;

final class SsoClientBundle extends AbstractBundle
{
    protected string $extensionAlias = 'sso_client';

    public function configure(DefinitionConfigurator $definition): void
    {
        $definition->rootNode()
            ->children()
                ->scalarNode('issuer')
                    ->info('SSO base URL, exactly as it appears in its discovery document (e.g. https://sso.janivanorpilla.com).')
                    ->defaultValue('%env(SSO_ISSUER)%')
                    ->cannotBeEmpty()
                ->end()
                ->scalarNode('client_id')
                    ->defaultValue('%env(SSO_CLIENT_ID)%')
                    ->cannotBeEmpty()
                ->end()
                ->scalarNode('client_secret')
                    ->info('Leave empty for a public client (e.g. a CLI or SPA); PKCE protects it.')
                    ->defaultValue('%env(default::SSO_CLIENT_SECRET)%')
                ->end()
                ->arrayNode('scopes')
                    ->scalarPrototype()->end()
                    ->defaultValue(['openid', 'profile', 'email', 'roles'])
                ->end()
                ->scalarNode('firewall')
                    ->info('Name of the firewall that uses sso_client.authenticator (for the "target" login parameter).')
                    ->defaultValue('main')
                ->end()
                ->scalarNode('default_target_path')
                    ->info('Where to go after login when no page was requested first.')
                    ->defaultValue('/')
                ->end()
                ->scalarNode('failure_path')
                    ->info('Redirect here when login fails (the error is in the session, as with form_login). Null shows a plain error page.')
                    ->defaultNull()
                ->end()
                ->scalarNode('post_logout_redirect_route')
                    ->info('Route to return to after signing out of the SSO. Null means the app\'s home page. Must be registered on the SSO client.')
                    ->defaultNull()
                ->end()
                ->scalarNode('user_provider')
                    ->info('Service implementing SsoUserProviderInterface.')
                    ->defaultValue('sso_client.session_user_provider')
                ->end()
                ->arrayNode('api_audiences')
                    ->info('Accepted "aud" values for bearer access tokens. Empty means this app\'s client_id.')
                    ->scalarPrototype()->end()
                ->end()
                ->integerNode('leeway')
                    ->info('Seconds of clock drift tolerated when checking token times.')
                    ->defaultValue(30)
                    ->min(0)
                ->end()
                ->scalarNode('http_client')->defaultValue('http_client')->end()
                ->scalarNode('cache')
                    ->info('Cache pool for discovery, signing keys and back-channel logouts. Must be shared by all app servers.')
                    ->defaultValue('cache.app')
                ->end()
                ->integerNode('cache_ttl')->defaultValue(3600)->min(60)->end()
                ->booleanNode('backchannel_logout')
                    ->info('End sessions in this app when the SSO reports a logout (needs the backchannel route).')
                    ->defaultTrue()
                ->end()
            ->end();
    }

    /**
     * @param array{issuer: string, client_id: string, client_secret: ?string, scopes: list<string>, firewall: string, default_target_path: string, failure_path: ?string, post_logout_redirect_route: ?string, user_provider: string, api_audiences: list<string>, leeway: int, http_client: string, cache: string, cache_ttl: int, backchannel_logout: bool} $config
     */
    public function loadExtension(array $config, ContainerConfigurator $container, ContainerBuilder $builder): void
    {
        $services = $container->services();

        $services->set('sso_client.discovery', OidcDiscovery::class)
            ->args([service($config['http_client']), service($config['cache']), $config['issuer'], $config['cache_ttl']])
            ->alias(OidcDiscovery::class, 'sso_client.discovery');

        $services->set('sso_client.jwks', JwksProvider::class)
            ->args([service($config['http_client']), service($config['cache']), service('sso_client.discovery'), service('clock'), $config['cache_ttl']])
            ->tag('kernel.reset', ['method' => 'reset']);

        $services->set('sso_client.token_verifier', TokenVerifier::class)
            ->args([service('sso_client.jwks'), service('clock'), $config['issuer'], $config['client_id'], $config['leeway']])
            ->alias(TokenVerifier::class, 'sso_client.token_verifier');

        $services->set('sso_client.client', OidcClient::class)
            ->args([service($config['http_client']), service('sso_client.discovery'), service('clock'), $config['client_id'], $config['client_secret'], $config['scopes']])
            ->alias(OidcClient::class, 'sso_client.client');

        $services->set('sso_client.pending_logins', PendingLoginStore::class)
            ->args([service('clock')]);

        $services->set('sso_client.token_storage', SsoTokenStorage::class)
            ->args([service('request_stack'), service('sso_client.client'), service('sso_client.token_verifier'), service('clock'), service('security.token_storage')->nullOnInvalid()])
            ->alias(SsoTokenStorage::class, 'sso_client.token_storage');

        $services->set('sso_client.session_user_provider', SessionUserProvider::class);
        $services->alias('sso_client.user_provider', $config['user_provider']);
        $services->alias(SsoUserProviderInterface::class, 'sso_client.user_provider');

        $services->set('sso_client.authenticator', OidcAuthenticator::class)
            ->args([
                service('sso_client.client'),
                service('sso_client.token_verifier'),
                service('sso_client.pending_logins'),
                service('sso_client.token_storage'),
                service('sso_client.user_provider'),
                service('router'),
                service('event_dispatcher'),
                $config['default_target_path'],
                $config['failure_path'],
            ]);

        $services->set('sso_client.bearer_authenticator', BearerTokenAuthenticator::class)
            ->args([service('sso_client.token_verifier'), service('sso_client.user_provider'), $config['api_audiences']]);

        $services->set('sso_client.backchannel_logout_registry', BackchannelLogoutRegistry::class)
            ->args([service($config['cache'])]);

        $services->set('sso_client.controller', SsoController::class)
            ->public()
            ->args([
                service('sso_client.client'),
                service('sso_client.pending_logins'),
                service('sso_client.token_verifier'),
                service('sso_client.backchannel_logout_registry'),
                service('event_dispatcher'),
                service('router'),
                $config['firewall'],
            ])
            ->tag('controller.service_arguments');

        $services->set('sso_client.logout_listener', SsoLogoutListener::class)
            ->args([service('sso_client.token_storage'), service('sso_client.discovery'), service('router'), $config['client_id'], $config['post_logout_redirect_route']])
            ->tag('kernel.event_listener', ['event' => LogoutEvent::class, 'priority' => 32]);

        if ($config['backchannel_logout']) {
            $services->set('sso_client.backchannel_logout_listener', BackchannelLogoutListener::class)
                ->args([service('sso_client.token_storage'), service('sso_client.backchannel_logout_registry')])
                ->tag('kernel.event_listener', ['event' => KernelEvents::REQUEST, 'priority' => 9]);
        }
    }
}

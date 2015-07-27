<?php
/**
 * @author    Anton Tokovoy
 * @copyright 2014
 */
namespace OAuth\SecurityProxyBundle\DependencyInjection;

use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\Reference;
use Symfony\Component\HttpKernel\DependencyInjection\Extension;
use Symfony\Component\DependencyInjection\Loader;

/**
 * This is the class that loads and manages your bundle configuration
 *
 * To learn more see {@link http://symfony.com/doc/current/cookbook/bundles/extension.html}
 */
class AtokovoyOAuthSecurityProxyExtension extends Extension
{
    /**
     * {@inheritDoc}
     */
    public function load(array $configs, ContainerBuilder $container)
    {
        $configuration = new Configuration();
        $config        = $this->processConfiguration($configuration, $configs);

        $loader = new Loader\YamlFileLoader($container, new FileLocator(__DIR__.'/../Resources/config'));
        $loader->load('services.yml');

        $entryPointDefinition = $container->getDefinition('oauth_proxy.security.entry_point');
        $entryPointDefinition->setArguments(array($config['http_unauthorized'], $config['token_type'], $config['realm']));

        $oauthListenerDefinition = $container->getDefinition('oauth_proxy.security.authentication.listener');
        $oauthListenerDefinition->addMethodCall('setHttpCode', array($config['http_unauthorized']));
        $oauthListenerDefinition->addMethodCall('setTokenType', array($config['token_type']));
        $oauthListenerDefinition->addMethodCall('setRealm', array($config['realm']));

        if (!empty($config['logger_channel'])) {
            $oauthListenerDefinition->addMethodCall('setLogger', array(new Reference('logger')));
            $oauthListenerDefinition->addTag('monolog.logger', array('channel' => $config['logger_channel']));

            $oauthProviderDefinition = $container->getDefinition('oauth_proxy.security.authentication.provider');
            $oauthProviderDefinition->addMethodCall('setLogger', array(new Reference('logger')));
            $oauthProviderDefinition->addTag('monolog.logger', array('channel' => $config['logger_channel']));
        }

        $userProviderDefinition = $container->getDefinition('oauth_proxy.user_provider.token');
        $userProviderDefinition->addArgument($config['user_class']);
        $userProviderDefinition->addArgument($config['token_type']);
    }
}

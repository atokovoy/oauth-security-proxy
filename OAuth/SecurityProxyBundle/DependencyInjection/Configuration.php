<?php
/**
 * @author    Anton Tokovoy
 * @copyright 2014
 */
namespace OAuth\SecurityProxyBundle\DependencyInjection;

use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;

/**
 * Class Configuration
 *
 * This is the class that validates and merges configuration from your app/config files
 *
 * To learn more see {@link http://symfony.com/doc/current/cookbook/bundles/extension.html#cookbook-bundles-extension-config-class}
 *
 * @package OAuth\SecurityProxyBundle\DependencyInjection
 */
class Configuration implements ConfigurationInterface
{
    /**
     * {@inheritDoc}
     */
    public function getConfigTreeBuilder()
    {
        $treeBuilder = new TreeBuilder();
        $rootNode    = $treeBuilder->root('atokovoy_o_auth_security_proxy');

        // Here you should define the parameters that are allowed to
        // configure your bundle. See the documentation linked above for
        // more information on that topic.

        $rootNode->children()
                 ->scalarNode('user_class')->isRequired()->end()
                 ->scalarNode('http_unauthorized')->defaultValue('401 Unauthorized')->end()
                 ->scalarNode('token_type')->defaultValue('Bearer')->end()
                 ->scalarNode('realm')->defaultValue('Realm')->end()
                 ->scalarNode('logger_channel')->defaultValue('')->end()
                 ->end();

        return $treeBuilder;
    }
}

<?php
/**
 * @author    Anton Tokovoy
 * @copyright 2014
 */
namespace OAuth\SecurityProxyBundle\DependencyInjection\Security\Factory;

use Symfony\Bundle\SecurityBundle\DependencyInjection\Security\Factory\SecurityFactoryInterface;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\DefinitionDecorator;
use Symfony\Component\DependencyInjection\Reference;

/**
 * Class OAuthFactory
 *
 * @package OAuth\SecurityProxyBundle\DependencyInjection\Security\Factory
 */
class OAuthFactory implements SecurityFactoryInterface
{
    /**
     * @param ContainerBuilder $container
     * @param mixed            $id
     * @param mixed            $config
     * @param mixed            $userProvider
     * @param mixed            $defaultEntryPoint
     *
     * @return array
     */
    public function create(ContainerBuilder $container, $id, $config, $userProvider, $defaultEntryPoint)
    {
        $providerId = 'security.authentication.provider.oauth_proxy.'.$id;
        $container
            ->setDefinition($providerId, new DefinitionDecorator('oauth_proxy.security.authentication.provider'))
            ->replaceArgument(0, new Reference($userProvider));

        $listenerId = 'security.authentication.listener.oauth_proxy.'.$id;
        $listener   = $container->setDefinition($listenerId, new DefinitionDecorator('oauth_proxy.security.authentication.listener'));

        return array($providerId, $listenerId, 'oauth_proxy.security.entry_point');
    }

    /**
     * @return string
     */
    public function getPosition()
    {
        return 'pre_auth';
    }

    /**
     * @return string
     */
    public function getKey()
    {
        return 'oauth_proxy';
    }

    /**
     * @param NodeDefinition $node
     */
    public function addConfiguration(NodeDefinition $node)
    {
    }
} 
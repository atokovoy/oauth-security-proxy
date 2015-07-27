<?php
/**
 * @author    Anton Tokovoy
 * @copyright 2014
 */
namespace OAuth\SecurityProxyBundle;

use OAuth\SecurityProxyBundle\DependencyInjection\Security\Factory\OAuthFactory;
use Symfony\Bundle\SecurityBundle\DependencyInjection\SecurityExtension;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\HttpKernel\Bundle\Bundle;

/**
 * Class AtokovoyOAuthSecurityProxyBundle
 *
 * @package OAuth\SecurityProxyBundle
 */
class AtokovoyOAuthSecurityProxyBundle extends Bundle
{
    public function build(ContainerBuilder $container)
    {
        parent::build($container);

        /** @var SecurityExtension $extension */
        $extension = $container->getExtension('security');
        $extension->addSecurityListenerFactory(new OAuthFactory());
    }
}

<?php
/**
 * @author    Anton Tokovoy
 * @copyright 2014
 */
namespace OAuth\SecurityProxyBundle\Security\User;

use Symfony\Component\Security\Core\User\UserInterface;

/**
 * Interface OAuthUserInterface
 *
 * @package OAuth\SecurityProxyBundle\Security\User
 */
interface OAuthUserInterface extends UserInterface
{
    /**
     * @return string
     */
    public function getToken();

    /**
     * @param string $token
     */
    public function setToken($token);

    /**
     * @param array $userData
     */
    public function loadUserData(array $userData);
} 
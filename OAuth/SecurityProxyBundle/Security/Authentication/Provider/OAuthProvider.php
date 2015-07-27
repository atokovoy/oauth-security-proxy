<?php
/**
 * @author    Anton Tokovoy
 * @copyright 2014
 */
namespace OAuth\SecurityProxyBundle\Security\Authentication\Provider;

use OAuth\SecurityProxyBundle\Security\Authentication\Token\OAuthToken;
use OAuth\SecurityProxyBundle\Security\User\OAuthUserProvider;
use Psr\Log\LoggerInterface;
use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserProviderInterface;

/**
 * Class OAuthProvider
 *
 * @package OAuth\SecurityProxyBundle\Security\Authentication\Provider
 */
class OAuthProvider implements AuthenticationProviderInterface
{
    /**
     * @var OAuthUserProvider
     */
    private $userProvider;

    /**
     * @var LoggerInterface
     */
    private $logger;

    /**
     * @param UserProviderInterface $userProvider
     */
    public function __construct(UserProviderInterface $userProvider)
    {
        $this->userProvider = $userProvider;
    }

    /**
     * @param LoggerInterface $logger
     */
    public function setLogger(LoggerInterface $logger)
    {
        $this->logger = $logger;
    }

    /**
     * @param TokenInterface $token
     *
     * @return OAuthToken|TokenInterface
     * @throws \Symfony\Component\Security\Core\Exception\AuthenticationException
     */
    public function authenticate(TokenInterface $token)
    {
        try {
            $tokenString = $token->getToken();
            $user        = $this->userProvider->loadUserByToken($tokenString);

            $token = new OAuthToken($user->getRoles());
            $token->setToken($tokenString);
            $token->setUser($user);
            $token->setAuthenticated(true);

            return $token;
        } catch (\Exception $e) {
            if ($this->logger) {
                $this->logger->alert('Can not authenticate user', array('message' => $e->getMessage()));
            }
        }
        throw new AuthenticationException('The OAuth authentication failed.');
    }

    /**
     * @param TokenInterface $token
     *
     * @return bool
     */
    public function supports(TokenInterface $token)
    {
        return $token instanceof OAuthToken;
    }
}
<?php
/**
 * @author    Anton Tokovoy
 * @copyright 2014
 */
namespace OAuth\SecurityProxyBundle\Security\User;

use Guzzle\Http\Client;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

/**
 * Class OAuthUserProvider
 *
 * @package OAuth\SecurityProxyBundle\Security\User
 */
class OAuthUserProvider implements UserProviderInterface
{
    private $httpClient;

    private $userClassName;

    private $tokenType;

    /**
     * @param Client $httpClient
     * @param string $userClassName
     * @param string $tokenType
     */
    public function __construct(Client $httpClient, $userClassName, $tokenType)
    {
        $this->httpClient    = $httpClient;
        $this->userClassName = $userClassName;
        $this->tokenType     = $tokenType;
    }

    /**
     * @param string $token
     *
     * @return array
     */
    protected function getAuthorizationHeader($token)
    {
        return array('Authorization' => $this->tokenType.' '.$token);
    }

    /**
     * Loads the user for the given username.
     *
     * This method must throw UsernameNotFoundException if the user is not
     * found.
     *
     * @param string $username The username
     *
     * @return UserInterface
     *
     * @see UsernameNotFoundException
     *
     * @throws UsernameNotFoundException if the user is not found
     *
     */
    public function loadUserByUsername($username)
    {
        throw new \Exception('Remote OAuthUserProvider does not support this method');
    }

    /**
     * @param string $token
     *
     * @return OAuthUser
     * @throws \Symfony\Component\Security\Core\Exception\UsernameNotFoundException
     */
    public function loadUserByToken($token)
    {
        $response = $this->httpClient->post(null, $this->getAuthorizationHeader($token))->send();

        $data = $response->json();

        try {
            $data = $data['data'];

            $user = new $this->userClassName();

            if (!$user instanceof OAuthUserInterface) {
                throw new UnsupportedUserException(sprintf('Instances of "%s" are not supported.', get_class($user)));
            }

            $user->setToken($token);
            $user->loadUserData($data);

            return $user;

        } catch (\Exception $exception) {
            throw new UsernameNotFoundException($exception->getMessage(), $exception->getCode(), $exception);
        }
    }

    /**
     * Refreshes the user for the account interface.
     *
     * It is up to the implementation to decide if the user data should be
     * totally reloaded (e.g. from the database), or if the UserInterface
     * object can just be merged into some internal array of users / identity
     * map.
     *
     * @param UserInterface $user
     *
     * @return UserInterface
     *
     * @throws UnsupportedUserException if the account is not supported
     */
    public function refreshUser(UserInterface $user)
    {
        if (!$user instanceof OAuthUserInterface) {
            throw new UnsupportedUserException(sprintf('Instances of "%s" are not supported.', get_class($user)));
        }

        return $this->loadUserByToken($user->getToken());
    }

    /**
     * Whether this provider supports the given user class
     *
     * @param string $class
     *
     * @return Boolean
     */
    public function supportsClass($class)
    {
        return $class === $this->userClassName;
    }
} 
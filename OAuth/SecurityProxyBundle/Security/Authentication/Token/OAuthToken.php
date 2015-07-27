<?php
/**
 * @author    Anton Tokovoy
 * @copyright 2014
 */
namespace OAuth\SecurityProxyBundle\Security\Authentication\Token;

use Symfony\Component\Security\Core\Authentication\Token\AbstractToken;

/**
 * Class OAuthToken
 *
 * @package OAuth\SecurityProxyBundle\Security\Authentication\Token
 */
class OAuthToken extends AbstractToken
{
    /**
     * @var string
     */
    protected $token;

    /**
     * @param string $token
     */
    public function setToken($token)
    {
        $this->token = $token;
    }

    /**
     * @return string
     */
    public function getToken()
    {
        return $this->token;
    }

    /**
     * @return mixed|string
     */
    public function getCredentials()
    {
        return $this->token;
    }
}
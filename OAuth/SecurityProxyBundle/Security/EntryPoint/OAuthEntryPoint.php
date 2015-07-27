<?php
/**
 * @author    Anton Tokovoy
 * @copyright 2014
 */
namespace OAuth\SecurityProxyBundle\Security\EntryPoint;

use OAuth\SecurityProxyBundle\HttpFoundation\ForbiddenResponse;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;

/**
 * Class OAuthEntryPoint
 *
 * @package OAuth\SecurityProxyBundle\Security\EntryPoint
 */
class OAuthEntryPoint implements AuthenticationEntryPointInterface
{
    private $httpCode;

    private $tokenType;

    private $realm;

    /**
     * @param mixed  $httpCode
     * @param string $tokenType
     * @param string $realm
     */
    public function __construct($httpCode, $tokenType, $realm)
    {
        $this->httpCode  = $httpCode;
        $this->tokenType = $tokenType;
        $this->realm     = $realm;
    }

    /**
     * @param Request                 $request
     * @param AuthenticationException $authException
     *
     * @return ForbiddenResponse|\Symfony\Component\HttpFoundation\Response
     */
    public function start(Request $request, AuthenticationException $authException = null)
    {
        return new ForbiddenResponse($this->httpCode, $this->tokenType, $this->realm);
    }
}
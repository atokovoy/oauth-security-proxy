<?php
/**
 * @author    Anton Tokovoy
 * @copyright 2014
 */
namespace OAuth\SecurityProxyBundle\Security\Firewall;

use OAuth\SecurityProxyBundle\HttpFoundation\ForbiddenResponse;
use OAuth\SecurityProxyBundle\Security\Authentication\Token\OAuthToken;

use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\SecurityContextInterface;
use Symfony\Component\Security\Http\Firewall\ListenerInterface;

/**
 * Class OAuthListener
 *
 * Security context listener
 *
 * @package OAuth\SecurityProxyBundle\Security\Firewall
 */
class OAuthListener implements ListenerInterface
{
    /**
     * @var \Symfony\Component\Security\Core\SecurityContextInterface
     */
    protected $securityContext;

    /**
     * @var \Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface
     */
    protected $authenticationManager;

    protected $httpCode;

    protected $tokenType;

    protected $realm;

    /**
     * @var LoggerInterface
     */
    protected $logger;

    /**
     * @param SecurityContextInterface       $securityContext
     * @param AuthenticationManagerInterface $authenticationManager
     */
    public function __construct(SecurityContextInterface $securityContext, AuthenticationManagerInterface $authenticationManager)
    {
        $this->securityContext       = $securityContext;
        $this->authenticationManager = $authenticationManager;
    }

    /**
     * It comes from OAuth Library
     *
     * @param Request $request
     *
     * @return null
     */
    protected function getBearerHeader(Request $request)
    {
        $header = null;
        if (!$request->headers->has('AUTHORIZATION')) {
            // The Authorization header may not be passed to PHP by Apache;
            // Trying to obtain it through apache_request_headers()
            if (function_exists('apache_request_headers')) {
                $headers = apache_request_headers();

                // Server-side fix for bug in old Android versions (a nice side-effect of this fix means we don't care about capitalization for Authorization)
                $headers = array_combine(array_map('ucwords', array_keys($headers)), array_values($headers));

                if (isset($headers['Authorization'])) {
                    $header = $headers['Authorization'];
                }
            }
        } else {
            $header = $request->headers->get('AUTHORIZATION');
        }

        return $header;
    }

    /**
     * @param Request $request
     *
     * @return bool
     */
    protected function getBearerTokenFromHeader(Request $request)
    {
        $tokenRegex = '/'.$this->tokenType.'\s(\S+)/';
        $header     = $this->getBearerHeader($request);

        if (!$header || 1 !== preg_match($tokenRegex, $header, $matches)) {
            return false;
        }

        return $matches[1];
    }

    /**
     * @param Request $request
     *
     * @return bool
     */
    protected function getBearerTokenFromQuery(Request $request)
    {
        if ($request->isMethod('POST')) {
            $bag = $request->request;
        } else {
            $bag = $request->query;
        }
        if (!$bag->has('access_token')) {
            return false;
        }

        return $bag->get('access_token');
    }

    /**
     * @param GetResponseEvent $event
     */
    protected function createForbiddenResponse(GetResponseEvent $event)
    {
        /**
         * @todo It should be deal of entry point
         */

        $response = new ForbiddenResponse($this->httpCode, $this->tokenType, $this->realm);

        $event->setResponse($response);
    }

    /**
     * @param LoggerInterface $logger
     */
    public function setLogger(LoggerInterface $logger)
    {
        $this->logger = $logger;
    }

    /**
     * @param mixed $httpCode
     */
    public function setHttpCode($httpCode)
    {
        $this->httpCode = $httpCode;
    }

    /**
     * @param mixed $realm
     */
    public function setRealm($realm)
    {
        $this->realm = $realm;
    }

    /**
     * @param mixed $tokenType
     */
    public function setTokenType($tokenType)
    {
        $this->tokenType = $tokenType;
    }

    /**
     * @param GetResponseEvent $event
     */
    public function handle(GetResponseEvent $event)
    {
        $request = $event->getRequest();

        $accessToken = $this->getBearerTokenFromHeader($request);
        if (false === $accessToken) {
            $accessToken = $this->getBearerTokenFromQuery($request);
        }

        if (false === $accessToken) {
            if ($this->logger) {
                $this->logger->alert(sprintf('Token type %s was not found neither header nor query', $this->tokenType));
            }

            $this->createForbiddenResponse($event);
        }

        $token = new OAuthToken();
        $token->setToken($accessToken);

        try {
            $authToken = $this->authenticationManager->authenticate($token);
            $this->securityContext->setToken($authToken);

            return;
        } catch (AuthenticationException $failed) {
            // ... you might log something here

            // To deny the authentication clear the token. This will redirect to the login page.
            // Make sure to only clear your token, not those of other authentication listeners.
            // $token = $this->securityContext->getToken();
            // if ($token instanceof WsseUserToken && $this->providerKey === $token->getProviderKey()) {
            //     $this->securityContext->setToken(null);
            // }
            // return;

            // Deny authentication with a '403 Forbidden' HTTP response

            if ($this->logger) {
                $this->logger->alert('Authentication exception', array('message' => $failed->getMessage()));
            }

            $this->createForbiddenResponse($event);
        } catch (\Exception $e) {
            if ($this->logger) {
                $this->logger->alert('Authentication exception', array('message' => $e->getMessage()));
            }
            $this->createForbiddenResponse($event);
        }

        // By default deny authorization
        $this->createForbiddenResponse($event);
    }
}
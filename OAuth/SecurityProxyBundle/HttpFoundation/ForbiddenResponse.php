<?php
/**
 * @author    Anton Tokovoy
 * @copyright 2014
 */
namespace OAuth\SecurityProxyBundle\HttpFoundation;

use Symfony\Component\HttpFoundation\JsonResponse;

/**
 * Class ForbiddenResponse
 *
 * @package OAuth\SecurityProxyBundle\HttpFoundation
 */
class ForbiddenResponse extends JsonResponse
{
    /**
     * @param mixed      $status
     * @param string     $tokenType
     * @param string     $realm
     * @param mixed|null $data
     */
    public function __construct($status, $tokenType, $realm, $data = null)
    {
        if (is_null($data)) {
            $data = array();
        }

        $defaultData = array('error' => 'access_denied', 'error_description' => 'OAuth2 authentication required');

        $data = array_merge($defaultData, $data);

        $header = sprintf('%s realm=%s', ucwords($tokenType), $realm);
        foreach ($data as $key => $value) {
            $header .= sprintf(', %s=%s', $key, $value);
        }

        $headers = array('WWW-Authenticate' => $header);

        parent::__construct($data, $status, $headers);
    }
} 
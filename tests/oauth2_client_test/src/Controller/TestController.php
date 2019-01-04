<?php

namespace Drupal\oauth2_client_test\Controller;

use Drupal\Core\Controller\ControllerBase;
use Drupal\Core\Url;
use Symfony\Component\HttpFoundation\RedirectResponse;

/**
 * Class TestController.
 *
 * @package Drupal\oauth2_client_test\Controller
 */
class TestController extends ControllerBase {

  /**
   * Trying test clients.
   *
   * Call them by opening in browser:
   *   - $base_url/oauth2/test/client-credentials
   *   - $base_url/oauth2/test/user-password
   *   - $base_url/oauth2/test/server-side
   *   - $base_url/oauth2/test/server-side-auto
   *   - $base_url/oauth2/test/wrong-client-id
   *   - $base_url/oauth2/test/wrong-client-secret
   *   - $base_url/oauth2/test/wrong-token-endpoint
   *   - $base_url/oauth2/test/wrong-auth-flow
   *   - $base_url/oauth2/test/wrong-username
   *   - $base_url/oauth2/test/wrong-password
   *   - $base_url/oauth2/test/wrong-scope
   *   - $base_url/oauth2/test/wrong-authorization-endpoint
   *   - $base_url/oauth2/test/wrong-redirect-uri.
   */
  public function callback($client_name) {
    try {
      // Get an access token and output it.
      $oauth2_client = oauth2_client_load($client_name);
      $access_token = $oauth2_client->getAccessToken();
      return ['#markup' => "access_token: $access_token"];
    }
    catch (\Exception $e) {
      return ['#markup' => $e->getMessage()];
    }
  }

  /**
   * Client Integration.
   *
   * Use the client 'client2' for getting an authorization code.
   * This is done with the help of the module oauth2_client,
   * because 'client2' is registered for it (its return_uri belongs
   * to oauth2_client).
   * Before jumping to $authentication_uri, register an internal
   * redirect with oauth2_client.
   *
   * Try it by opening in browser:
   *   - $base_url/oauth2/test-client-integration
   */
  public function clientIntegration() {
    $state = \Drupal::csrfToken()->get('test_client');
    oauth2_client_set_redirect($state, [
      'uri' => 'oauth2/test-authorized',
      'params' => [
        'extra_param' => 'This will be appended to the request on redirect.',
      ],
    ]);

    $query_params = [
      'response_type' => 'code',
      'client_id' => 'client2',
      'redirect_uri' => oauth2_client_get_redirect_uri(),
      'state' => $state,
    ];
    $endpoint = Url::fromUserInput('oauth2/authorize', ['absolute' => TRUE])->toString();
    $authentication_uri = $endpoint . '?' . http_build_query($query_params);
    return new RedirectResponse($authentication_uri);
  }

  /**
   * Authorized.
   *
   * The oauth2 server will redirect to the registered redirect_uri,
   * which is handled by the oauth2_client, but then oauth2_client
   * will redirect to the path 'oauth2/test/authorized', which comes
   * here. This is because we registered a redirect on the oauth2_client
   * before jumping to $authentication_uri. While redirecting, oauth2_client
   * will also append to the request the 'extra_param'.
   */
  public function authorized() {
    if (!\Drupal::csrfToken()->validate($_GET['state'], 'test_client')) {
      return ['#markup' => "The parameter 'state' is wrong.\n"];
    }
    $extra_param = $_GET['extra_param'];
    print "extra_param: $extra_param <br/>\n";

    $options = [
      'method' => 'POST',
      'data' => http_build_query([
        'grant_type' => 'authorization_code',
        'code' => $_GET['code'],
        'redirect_uri' => oauth2_client_get_redirect_uri(),
      ]),
      'headers' => [
        'Content-Type' => 'application/x-www-form-urlencoded',
        'Authorization' => 'Basic ' . base64_encode('client2:secret2'),
      ],
      'context' => stream_context_create([
        'ssl' => [
          'verify_peer' => FALSE,
          'verify_peer_name' => FALSE,
        ],
      ]),
    ];
    $token_endpoint = Url::fromUserInput('oauth2/token', ['absolute' => TRUE])->toString();
    $result = \Drupal::httpClient()->get($token_endpoint, $options);
    $token = json_decode($result->getBody()->getContents());
    return ['#markup' => 'access_token: ' . $token->access_token];
  }

}

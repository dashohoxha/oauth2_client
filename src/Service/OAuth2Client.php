<?php
namespace Drupal\oauth2_client\Service;

use Drupal\Core\Url;
use GuzzleHttp\ClientInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\Serializer\Serializer;
use Symfony\Component\Serializer\Encoder\JsonEncoder;
use Symfony\Component\Serializer\Normalizer\GetSetMethodNormalizer;

/**
 * The class OAuth2Client is used to get authorization from
 * an OAuth2 server.
 *
 * It can use authorization flows: server-side, client-credentials
 * and user-password. The details for each case are passed
 * to the constructor. All the three cases need a client_id,
 * a client_secret, and a token_endpoint. There can be an optional
 * scope as well.
 */
class OAuth2Client implements OAuth2ClientInterface {

  /**
   * Unique identifier of an OAuth2Client object.
   */
  protected $id = NULL;

  /**
   * Associative array of the parameters that are needed
   * by the different types of authorization flows.
   *  - auth_flow :: server-side | client-credentials | user-password
   *  - client_id :: Client ID, as registered on the oauth2 server
   *  - client_secret :: Client secret, as registered on the oauth2 server
   *  - token_endpoint :: something like:
   *       https://oauth2_server.example.org/oauth2/token
   *  - authorization_endpoint :: somethig like:
   *       https://oauth2_server.example.org/oauth2/authorize
   *  - redirect_uri :: something like:
   *       url('oauth2/authorized', array('absolute' => TRUE)) or
   *       https://oauth2_client.example.org/oauth2/authorized
   *  - scope :: requested scopes, separated by a space
   *  - username :: username of the resource owner
   *  - password :: password of the resource owner
   *  - skip-ssl-verification :: Skip verification of the SSL connection (needed for testing).
   */
  protected $params = [
    'auth_flow' => NULL,
    'client_id' => NULL,
    'client_secret' => NULL,
    'token_endpoint' => NULL,
    'authorization_endpoint' => NULL,
    'redirect_uri' => NULL,
    'scope' => NULL,
    'username' => NULL,
    'password' => NULL,
    'skip-ssl-verification' => FALSE,
  ];

  /**
   * Associated array that keeps data about the access token.
   */
  protected $token = [
    'access_token' => NULL,
    'expires_in' => NULL,
    'token_type' => NULL,
    'scope' => NULL,
    'refresh_token' => NULL,
    'expiration_time' => NULL,
  ];

  /**
   * The HTTP Request client
   *
   * @var \GuzzleHttp\ClientInterface
   */
  protected $httpClient;

  /**
   * The Request Stack
   *
   * @var \Symfony\Component\HttpFoundation\RequestStack
   */
  protected $requestStack;

  /**
   * Construct an OAuth2Client object.
   *
   * @param \GuzzleHttp\ClientInterface $httpClient
   *   The HTTP Request client
   * @param \Symfony\Component\HttpFoundation\RequestStack $requestStack
   *   The Request Stack
   */
  public function __construct(ClientInterface $httpClient, RequestStack $requestStack) {
    $this->httpClient = $httpClient;
    $this->requestStack = $requestStack;
  }

  /**
   * {@inheritdoc}
   */
  public function init($params = NULL, $id = NULL) {
    if ($params) {
      $this->params = $params + $this->params;
    }

    if (!$id) {
      $id = md5($this->params['token_endpoint'] .
        $this->params['client_id'] .
        $this->params['auth_flow']);
    }
    $this->id = $id;

    // Get the token data from the session, if it is stored there.
    if (isset($_SESSION['oauth2_client']['token'][$this->id])) {
      $this->token = $_SESSION['oauth2_client']['token'][$this->id] + $this->token;
    }
  }

  /**
   * {@inheritdoc}.
   */
  public function clearToken() {
    if (isset($_SESSION['oauth2_client']['token'][$this->id])) {
      unset($_SESSION['oauth2_client']['token'][$this->id]);
    }

    $this->token = [
      'access_token' => NULL,
      'expires_in' => NULL,
      'token_type' => NULL,
      'scope' => NULL,
      'refresh_token' => NULL,
      'expiration_time' => NULL,
    ];
  }

  /**
   * {@inheritdoc}
   */
  public function getAccessToken($redirect = TRUE) {
    // Check wheather the existing token has expired.
    // We take the expiration time to be shorter by 10 sec
    // in order to account for any delays during the request.
    // Usually a token is valid for 1 hour, so making
    // the expiration time shorter by 10 sec is insignificant.
    // However it should be kept in mind during the tests,
    // where the expiration time is much shorter.
    $expiration_time = $this->token['expiration_time'];
    if ($expiration_time > (time() + 10)) {
      // The existing token can still be used.
      return $this->token['access_token'];
    }

    try {
      // Try to use refresh_token.
      $token = $this->getTokenRefreshToken();
    }
    catch (\Exception $e) {
      // Get a token.
      switch ($this->params['auth_flow']) {
        case 'client-credentials':
          $token = $this->getToken([
            'grant_type' => 'client_credentials',
            'scope' => $this->params['scope'],
          ]);

          break;

        case 'user-password':
          $token = $this->getToken([
            'grant_type' => 'password',
            'username' => $this->params['username'],
            'password' => $this->params['password'],
            'scope' => $this->params['scope'],
          ]);

          break;

        case 'server-side':
          if ($redirect) {
            $token = $this->getTokenServerSide();
          }
          else {
            $this->clearToken();
            return NULL;
          }
          break;

        default:
          throw new \Exception(t(
            'Unknown authorization flow "@auth_flow". Supported values for auth_flow are: client-credentials, user-password, server-side.',
            ['@auth_flow' => $this->params['auth_flow']]
          ));

          break;
      }
    }

    if(isset($token['access_token'])) {
      // Some providers do not return an 'expires_in' value, so we
      // set a default of an hour. If the token expires dies within that time,
      // the system will request a new token automatically.
      $token['expiration_time'] = isset($token['expires_in']) ? REQUEST_TIME + $token['expires_in'] : REQUEST_TIME + 3600;
    }

    // Store the token (on session as well).
    $this->token = $token;
    $_SESSION['oauth2_client']['token'][$this->id] = $token;

    // Redirect to the original path (if this is a redirection
    // from the server-side flow).
    self::redirect();

    // Return the token.
    return $token['access_token'];
  }

  /**
   * {@inheritdoc}
   */
  public static function setRedirect($state, $redirect =NULL) {
    if ($redirect == NULL) {
      $redirect = [
        'uri' => \Drupal::request()->getRequestUri(),
        'client' => 'oauth2_client',
      ];
    }

    if (!isset($redirect['client'])) {
      $redirect['client'] = 'external';
    }

    $_SESSION['oauth2_client']['redirect'][$state] = $redirect;
  }

  /**
   * {@inheritdoc}
   */
  public static function redirect($clean = TRUE) {
    if (!\Drupal::service('request_stack')->getCurrentRequest()->get('state')) {
      return;
	}
    $state = \Drupal::service('request_stack')->getCurrentRequest()->get('state');

    if (!isset($_SESSION['oauth2_client']['redirect'][$state])) {
      return;
    }

    $redirect = $_SESSION['oauth2_client']['redirect'][$state];

    if ($redirect['client'] != 'oauth2_client') {
      unset($_SESSION['oauth2_client']['redirect'][$state]);

	  $params = isset($redirect['params']) ? $redirect['params'] : [];
	  $params = $params + \Drupal::request()->query->all();

      $url = Url::fromUri($redirect['uri'], ['query' => $params]);
      $redirect = new RedirectResponse($url);
      $redirect->send();
    }
    else {
      $params =  \Drupal::request()->query->all();
      if ($clean) {
        unset($_SESSION['oauth2_client']['redirect'][$state]);
        unset($params['code']);
        unset($params['state']);
     }

	  if(isset($redirect['params'])) {
		  $params = $redirect['params'] + $params;
      }

      $url = Url::fromUri('internal:' . $redirect['uri'], ['query' => $params]);
      $redirect = new RedirectResponse($url->toString());
      $redirect->send();
    }
  }

  /**
   * Get a new access_token using the refresh_token.
   *
   * This is used for the server-side and user-password
   * flows (not for client-credentials, there is no
   * refresh_token in it).
   */
  protected function getTokenRefreshToken() {
    if (!$this->token['refresh_token']) {
      throw new \Exception(t('There is no refresh_token.'));
    }

    return $this->getToken([
      'grant_type' => 'refresh_token',
      'refresh_token' => $this->token['refresh_token'],
    ]);
  }

  /**
   * Get an access_token using the server-side (authorization code) flow.
   *
   * This is done in two steps:
   *   - First, a redirection is done to the authentication
   *     endpoint, in order to request an authorization code.
   *   - Second, using this code, an access_token is requested.
   *
   * There are lots of redirects in this case and this part is the most
   * tricky and difficult to understand of the oauth2_client, so let
   * me try to explain how it is done.
   *
   * Suppose that in the controller of the path 'test/xyz'
   * we try to get an access_token:
   *     $client = oauth2_client_load('server-side-test');
   *     $access_token = $client->getAccessToken();
   * or:
   *     $client = new OAuth2\Client(array(
   *         'token_endpoint' => 'https://oauth2_server/oauth2/token',
   *         'client_id' => 'client1',
   *         'client_secret' => 'secret1',
   *         'auth_flow' => 'server-side',
   *         'authorization_endpoint' => 'https://oauth2_server/oauth2/authorize',
   *         'redirect_uri' => 'https://oauth2_client/oauth2/authorized',
   *       ));
   *     $access_token = $client->getAccessToken();
   *
   * From getAccessToken() we come to this function, getTokenServerSide(),
   * and since there is no $_GET['code'], we redirect to the authentication
   * url, but first we save the current path in the session:
   *   $_SESSION['oauth2_client']['redirect'][$state]['uri'] = 'test/xyz';
   *
   * Once the authentication and authorization is done on the server, we are
   * redirected by the server to the redirect uri: 'oauth2/authorized'.  In
   * the controller of this path we redirect to the saved path 'test/xyz'
   * (since $_SESSION['oauth2_client']['redirect'][$state] exists), passing
   * along the query parameters sent by the server (which include 'code',
   * 'state', and maybe other parameters as well.)
   *
   * Now the code: $access_token = $client->getAccessToken(); is
   * called again and we come back for a second time to the function
   * getTokenServerSide(). However this time we do have a
   * $_GET['code'], so we get a token from the server and return it.
   *
   * Inside the function getAccessToken() we save the returned token in
   * session and then, since $_SESSION['oauth2_client']['redirect'][$state]
   * exists, we delete it and make another redirect to 'test/xyz'.  This third
   * redirect is in order to have in browser the original url, because from
   * the last redirect we have something like this:
   * 'test/xyz?code=8557&state=3d7dh3&....'
   *
   * We come again for a third time to the code
   *     $access_token = $client->getAccessToken();
   * But this time we have a valid token already saved in session,
   * so the $client can find and return it without having to redirect etc.
   */
  protected function getTokenServerSide() {
    if (!$this->requestStack->getCurrentRequest()->get('code')) {
      $url = $this->getAuthenticationUrl();

      $url = Url::fromUri($url);
      $redirect = new RedirectResponse($url->toString());
      $redirect->send();
    }
    else {
      // Check the query parameter 'state'.
      $state = $this->requestStack->getCurrentRequest()->get('state');
      if (!$state || !isset($_SESSION['oauth2_client']['redirect'][$state])) {
        throw new \Exception(t("Wrong query parameter 'state'."));
      }

      // Get and return a token.
      return $this->getToken([
        'grant_type' => 'authorization_code',
        'code' => $this->requestStack->getCurrentRequest()->get('code'),
        'redirect_uri' => $this->params['redirect_uri'],
      ]);
    }
  }

  /**
   * Return the authentication url (used in case of the server-side flow).
   */
  protected function getAuthenticationUrl() {
    $state = md5(uniqid(rand(), TRUE));
    $query_params = [
      'response_type' => 'code',
      'client_id' => $this->params['client_id'],
      'redirect_uri' => $this->params['redirect_uri'],
      'state' => $state
    ];

    if ($this->params['scope']) {
      $query_params['scope'] = $this->params['scope'];
    }

    $endpoint = $this->params['authorization_endpoint'];
    self::setRedirect($state);
    return $endpoint . '?' . http_build_query($query_params);
  }

  /**
   * Get and return an access token for the grant_type given in $params.
   */
  protected function getToken($data) {
    if (array_key_exists('scope', $data) && $data['scope'] === NULL) {
      unset($data['scope']);
    }

    $client_id = $this->params['client_id'];
    $client_secret = $this->params['client_secret'];
    $token_endpoint = $this->params['token_endpoint'];

	$data['client_id'] = $client_id;
	$data['client_secret'] = $client_secret;

    $options = [
      'form_params' => $data,
      'headers' => [
        'Content-Type' => 'application/x-www-form-urlencoded',
        'Authorization' => 'Basic ' . base64_encode("$client_id:$client_secret"),
      ],
    ];
    if ($this->params['skip-ssl-verification']) {
      $options['context'] = stream_context_create([
        'ssl' => [
          'verify_peer' => FALSE,
          'verify_peer_name' => FALSE,
        ]
      ]);
    }

    $response = $this->httpClient->request('POST', $token_endpoint, $options);
    $response_data = (string) $response->getBody();

    if (empty($response_data)) {
      throw new \Exception(
        t('Failed to get an access token of grant_type @grant_type.', ['@grant_type' => $data['grant_type']]) .
        PHP_EOL .
        t('Error: @result_error', ['@result_error' => $result->error])
      );
    }
 
    $serializer = new Serializer(array(new GetSetMethodNormalizer()), array('json' => new JsonEncoder()));

    return $serializer->decode($response_data, 'json');
  }
}

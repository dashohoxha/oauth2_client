<?php

namespace Drupal\Tests\oauth2_client\Functional;

use Drupal\Tests\BrowserTestBase;
use Drupal\user\Entity\User;

/**
 * Test OAuth2 Client.
 *
 * @group oauth2_client
 */
class OAuth2ClientTest extends BrowserTestBase {

  protected $modules = ['oauth2_client_test', 'libraries'];

  /**
   * User storage instance.
   *
   * @var \Drupal\user\UserStorageInterface
   */
  protected $userStorage;

  public static function getInfo() {
    return array(
      'name' => 'OAuth2 Client',
      'description' => 'Tests basic OAuth2 Client functionality.',
      'group' => 'OAuth2',
    );
  }

  public function setUp() {
    parent::setUp();
    $this->userStorage = \Drupal::entityTypeManager()->getStorage('user');
  }

  public function testGetAccessToken() {
    $this->clientCredentialsFlow();
    $this->userPasswordFlow();
    $this->serverSideFlow();
    $this->clientIntegration();
    $this->errorCases();
  }

  /**
   * Get and return a token from the given test client.
   */
  protected function getToken($client) {
    $result = $this->drupalGet('oauth2/test/' . $client);
    $this->assertSession()->responseMatches('/^access_token: /');
    $token = str_replace('access_token: ', '', $result);
    $token = trim($token);
    $this->assertNotEquals('', $token, 'Token is not empty.');
    return $token;
  }

  /**
   * Test the client-credentials flow.
   */
  public function clientCredentialsFlow() {
    $token1 = $this->getToken('client-credentials');
    $token2 = $this->getToken('client-credentials');
    $this->assertEquals($token2, $token1, 'The same cached token is used, while it has not expired yet.');

    // Wait for the token to expire.
    sleep(10);
    $token3 = $this->getToken('client-credentials');
    $this->assertNotEquals($token3, $token1, 'Getting a new token, client-credential flow has no refresh token.');
  }

  /**
   * Test the user-password flow.
   */
  public function userPasswordFlow() {
    $token1 = $this->getToken('user-password');
    $token2 = $this->getToken('user-password');
    $this->assertEquals($token2, $token1, 'The same cached token is used, while it has not expired yet.');

    // Wait for the token to expire.
    sleep(10);
    $token3 = $this->getToken('user-password');
    $this->assertNotEquals($token3, $token1, 'Getting a new token from refresh_token.');

    // Wait for the refresh_token to expire.
    sleep(30);
    $token4 = $this->getToken('user-password');
  }

  /**
   * Test the server-side flow.
   *
   * For this test we are using 'client2' which has
   * automatic authorization enabled.
   */
  public function serverSideFlow() {
    $users = $this->userStorage->loadByProperties(['name' => 'user1']);
    $user = reset($users);
    $this->drupalLogin($user);
    $token1 = $this->getToken('server-side-auto');
    $token2 = $this->getToken('server-side-auto');
    $this->assertEquals($token2, $token1, 'The same cached token is used, while it has not expired yet.');

    // Wait for the token to expire.
    sleep(10);
    $token3 = $this->getToken('server-side-auto');
    $this->assertNotEquals($token3, $token1, 'Getting a new token from refresh_token.');

    // Wait for the refresh_token to expire.
    sleep(30);
    $token4 = $this->getToken('server-side-auto');
  }

  /**
   * Test client integration.
   */
  public function clientIntegration() {
    $result = $this->drupalGet('oauth2/test-client-integration');
    $this->assertText('access_token: ');
    $this->assertText('extra_param: This will be appended to the request on redirect.');
  }

  /**
   * Test error cases.
   */
  public function errorCases() {
    $error_cases = array(
      'wrong-client-id',
      'wrong-client-secret',
      'wrong-token-endpoint',
      'wrong-username',
      'wrong-password',
      'wrong-scope',
    );
    foreach ($error_cases as $error_case) {
      $this->drupalGet('oauth2/test/' . $error_case);
      $this->assertText('Failed to get an access token');
    }

    // wrong-auth-flow
    $this->drupalGet('oauth2/test/wrong-auth-flow');
    $this->assertText('Unknown authorization flow');

    // wrong-authorization-endpoint
    // wrong-redirect-uri
  }

}

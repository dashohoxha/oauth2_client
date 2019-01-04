<?php

namespace Drupal\oauth2_client\Controller;

use Drupal\Core\Controller\ControllerBase;
use Drupal\Core\Routing\ResettableStackedRouteMatchInterface;
use Drupal\oauth2_client\Service\OAuth2Client;
use Symfony\Component\DependencyInjection\ContainerInterface;

class OAuth2ClientController extends ControllerBase implements OAuth2ClientControllerInterface {

  /**
   * The Current Route Match
   *
   * @var \Drupal\Core\Routing\ResettableStackedRouteMatchInterface
   */
  protected $currentRouteMatch;

  /**
   * Create an OAuth2ClientController object
   *
   * @param \Drupal\Core\Routing\ResettableStackedRouteMatchInterface $currentRouteMatch
   *   The Current Route Match
   */
  public function __construct(ResettableStackedRouteMatchInterface $currentRouteMatch) {
    $this->currentRouteMatch = $currentRouteMatch;
  }

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container) {
    return new static(
      $container->get('current_route_match')
    );
  }

  /**
   * {@inheritdoc}
   */
  public function redirectUrlPage() {
    // If there is any error in the server response, display it.
    if ($this->currentRouteMatch->getParameter('error')) {
      $error = $this->currentRouteMatch->getParameter('error');
      $error_description = $this->currentRouteMatch->getParameter('error_description');
      $message = $this->t('Error: @error: @error_description', ['@error' => $error, '@error_description' => $error_description]);

      $this->messenger()->addError($message);
    }

    // Redirect to the client that started the authentication.
    OAuth2Client::redirect(FALSE);
    return [
	    '#markup' => 'Redirect failed',
    ];
  }

}

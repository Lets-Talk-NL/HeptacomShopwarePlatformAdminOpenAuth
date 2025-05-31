<?php

declare(strict_types=1);

namespace Heptacom\AdminOpenAuth\Service\HttpClient\Middleware;

use Heptacom\AdminOpenAuth\Contract\Client\ClientContract;
use Heptacom\AdminOpenAuth\Contract\Client\RefreshTokenContract;
use Heptacom\AdminOpenAuth\Contract\TokenPair;
use Heptacom\AdminOpenAuth\Contract\UserTokenInterface;
use Heptacom\AdminOpenAuth\Database\UserTokenEntity;
use Heptacom\AdminOpenAuth\Exception\ClientFeatureNotSupportedException;
use Shopware\Core\Framework\Context;

final class UserAuthorizationMiddleware extends AuthorizationMiddleware
{
    public function __construct(
        protected readonly string $clientId,
        protected readonly ClientContract $client,
        protected readonly string $userId,
        protected readonly UserTokenInterface $userToken,
        protected readonly Context $context,
    ) {
        parent::__construct($client);
    }

    protected function getToken(): ?TokenPair
    {
        $userToken = $this->userToken->getToken($this->userId, $this->clientId, $this->context);

        if (!$userToken instanceof UserTokenEntity) {
            return null;
        }

        $token = new TokenPair();
        $token->accessToken = $userToken->accessToken;
        $token->refreshToken = $userToken->refreshToken;
        $token->expiresAt = $userToken->expiresAt;

        return $token;
    }

    protected function storeRefreshedToken(TokenPair $token): void
    {
        $this->userToken->setToken($this->userId, $this->clientId, $token, $this->context);
    }
}

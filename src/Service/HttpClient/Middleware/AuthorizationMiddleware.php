<?php

declare(strict_types=1);

namespace Heptacom\AdminOpenAuth\Service\HttpClient\Middleware;

use Heptacom\AdminOpenAuth\Contract\Client\ClientContract;
use Heptacom\AdminOpenAuth\Contract\Client\RefreshTokenContract;
use Heptacom\AdminOpenAuth\Contract\Client\StandaloneClientContract;
use Heptacom\AdminOpenAuth\Contract\TokenPair;
use Heptacom\AdminOpenAuth\Contract\UserTokenInterface;
use Heptacom\AdminOpenAuth\Database\UserTokenEntity;
use Heptacom\AdminOpenAuth\Exception\ClientFeatureNotSupportedException;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Shopware\Core\Framework\Context;

final class AuthorizationMiddleware implements HttpClientMiddlewareInterface
{
    /**
     * @param string[]|null $clientScopes Only for none-user clients
     */
    public function __construct(
        protected readonly string $clientId,
        protected readonly ClientContract $client,
        protected readonly UserTokenInterface $userToken,
        protected readonly Context $context,
        protected readonly ?string $userId = null,
        protected readonly ?array $clientScopes = null,
    ) {
    }

    public function process(RequestInterface $request, ClientInterface $handler): ResponseInterface
    {
        $token = $this->getToken();

        if (!$token instanceof TokenPair) {
            throw new \Exception(); // todo: custom exception
        }

        $request = $this->client->authorizeRequest($request, $token);

        return $handler->sendRequest($request);
    }

    private function getToken(): ?TokenPair
    {
        return $this->userId === null
            ? $this->getClientToken()
            : $this->getUserToken();
    }

    private function getClientToken(): ?TokenPair
    {
        if (!$this->client instanceof StandaloneClientContract) {
            throw new ClientFeatureNotSupportedException(
                $this->client::class,
                StandaloneClientContract::class,
                1748642863
            );
        }

        // todo: implement caching
        return $this->client->getClientToken($this->clientScopes);
    }

    private function getUserToken(): ?TokenPair
    {
        $userToken = $this->userToken->getToken($this->userId, $this->clientId, $this->context);

        if (!$userToken instanceof UserTokenEntity) {
            return null;
        }

        $token = new TokenPair();
        $token->accessToken = $userToken->accessToken;
        $token->refreshToken = $userToken->refreshToken;
        $token->expiresAt = $userToken->expiresAt;

        if ($this->needsRefresh($token)) {
            if ($this->client instanceof RefreshTokenContract && $token->refreshToken !== null) {
                $token = $this->client->refreshToken($token->refreshToken);

                $this->userToken->setToken($this->userId, $this->clientId, $token, $this->context);
            } else {
                // todo: check if to use a different exception
                throw new ClientFeatureNotSupportedException(
                    $this->client::class,
                    RefreshTokenContract::class,
                    1748643468
                );
            }
        }

        return $token;
    }

    private function needsRefresh(TokenPair $token): bool
    {
        return $token->expiresAt !== null && new \DateTime() > $token->expiresAt;
    }
}

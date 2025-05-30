<?php

declare(strict_types=1);

namespace Heptacom\AdminOpenAuth\Service\HttpClient;

use Heptacom\AdminOpenAuth\Contract\Client\ClientContract;
use Heptacom\AdminOpenAuth\Contract\Client\RequestAuthorizationContract;
use Heptacom\AdminOpenAuth\Contract\Client\StandaloneClientContract;
use Heptacom\AdminOpenAuth\Contract\ClientLoaderInterface;
use Heptacom\AdminOpenAuth\Contract\UserTokenInterface;
use Heptacom\AdminOpenAuth\Exception\ClientFeatureNotSupportedException;
use Heptacom\AdminOpenAuth\Exception\LoadClientException;
use Heptacom\AdminOpenAuth\Service\HttpClient\Middleware\AuthorizationMiddleware;
use Heptacom\AdminOpenAuth\Service\HttpClient\Middleware\HttpClientMiddlewareInterface;
use Psr\Http\Client\ClientInterface;
use Shopware\Core\Framework\Context;

final class AuthorizedHttpClientFactory
{
    /**
     * @var array<string, AuthorizedHttpClient>
     */
    private array $httpClients = [];

    /**
     * @var HttpClientMiddlewareInterface[]
     */
    private readonly array $middlewares;

    /**
     * @param iterable<HttpClientMiddlewareInterface> $middlewares
     */
    public function __construct(
        private readonly ClientLoaderInterface $clientLoader,
        private readonly UserTokenInterface $userToken,
        private readonly ClientInterface $httpClient,
        iterable $middlewares,
    ) {
        $this->middlewares = \array_filter(
            \iterator_to_array($middlewares),
            static fn (HttpClientMiddlewareInterface $middleware): bool => !$middleware instanceof AuthorizationMiddleware,
        );
    }

    /**
     * Creates a client dedicated for machine-to-machine communication.
     * The credentials will be fetched from the configured client.
     * @param string[]|null $scopes Scopes to be requested for the client. If null, the configured scopes of the client will be used.
     * @return ClientInterface
     * @throws LoadClientException|ClientFeatureNotSupportedException
     */
    public function forClient(string $clientId, Context $context, ?array $scopes = null): ClientInterface
    {
        $client = $this->loadClient($clientId, StandaloneClientContract::class, $context);

        return $this->getHttpClient(
            $clientId,
            $client,
            $context,
            scopes: $scopes,
        );
    }

    /**
     * Creates a client authenticated for a specific user.
     * @throws LoadClientException|ClientFeatureNotSupportedException
     */
    public function forUser(string $clientId, string $userId, Context $context): ClientInterface
    {
        $client = $this->loadClient($clientId, RequestAuthorizationContract::class, $context);

        return $this->getHttpClient(
            $clientId,
            $client,
            $context,
            userId: $userId,
        );
    }

    /**
     * @param string $clientId
     * @param class-string $feature
     * @throws LoadClientException|ClientFeatureNotSupportedException
     */
    private function loadClient(string $clientId, string $feature, Context $context): ClientContract
    {
        $client = $this->clientLoader->load($clientId, $context);

        if (!$client instanceof $feature) {
            throw new ClientFeatureNotSupportedException($client::class, $feature);
        }

        return $client;
    }

    /**
     * @param string[]|null $scopes
     */
    private function getHttpClient(
        string $clientId,
        ClientContract $client,
        Context $context,
        ?string $userId = null,
        ?array $scopes = null,
    ): AuthorizedHttpClient
    {
        $cacheKey = $clientId;

        if ($userId !== null) {
            $cacheKey .= '_' . $userId;
        }

        if ($scopes !== null && $scopes !== []) {
            $cacheKeyScopes = $scopes;
            \sort($cacheKeyScopes);
            $cacheKey .= '_' . sha1(implode(' ', $cacheKeyScopes));
        }

        $this->httpClients[$cacheKey] ??= new AuthorizedHttpClient(
            $this->httpClient,
            [
                ...$this->middlewares,
                $this->getAuthorizationMiddleware($clientId, $client, $userId, $scopes, $context)
            ]
        );

        return $this->httpClients[$cacheKey];
    }

    /**
     * @param string[]|null $scopes
     */
    private function getAuthorizationMiddleware(
        string $clientId,
        ClientContract $client,
        ?string $userId,
        ?array $scopes,
        Context $context,
    ): HttpClientMiddlewareInterface
    {
        return new AuthorizationMiddleware(
            $clientId,
            $client,
            $this->userToken,
            $context,
            $userId,
            $scopes
        );
    }
}

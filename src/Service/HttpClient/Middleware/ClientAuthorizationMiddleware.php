<?php

declare(strict_types=1);

namespace Heptacom\AdminOpenAuth\Service\HttpClient\Middleware;

use Heptacom\AdminOpenAuth\Contract\Client\ClientContract;
use Heptacom\AdminOpenAuth\Contract\Client\StandaloneClientContract;
use Heptacom\AdminOpenAuth\Contract\TokenPair;
use Heptacom\AdminOpenAuth\Exception\ClientFeatureNotSupportedException;

final class ClientAuthorizationMiddleware extends AuthorizationMiddleware
{
    public function __construct(
        ClientContract $client,
        protected readonly ?array $clientScopes = null,
    ) {
        parent::__construct($client);
    }

    protected function getToken(): ?TokenPair
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

    protected function storeRefreshedToken(TokenPair $token): void
    {
        // todo: implement caching
    }
}

<?php

declare(strict_types=1);

namespace G\Csrf\TokenStorage;

interface TokenStorageInterface
{
    /**
     * Store a token in the storage with an optional key.
     * If the key is null, it will be stored as a default token.
     *
     * @param string $token The token to store.
     * @param null|string $key The key under which to store the token.
     * If null, the token will be stored as a default token.
     *
     * @return void
     */
    public function setToken(string $token, ?string $key = null): void;

    /**
     * Retrieve a token from the storage by its key.
     *
     * @param null|string $key The key under which to retrieve the token.
     * If null, the default token will be retrieved.
     * @return null|string The token if found, null otherwise.
     */
    public function getToken(?string $key = null): ?string;

    /**
     * Check if a token exists in the storage.
     *
     * @param string $token The token to check.
     * @param null|string $key The key under which to check the token.
     * If null, the default token will be checked.
     * @return bool True if the token exists, false otherwise.
     */
    public function hasToken(string $token, ?string $key = null): bool;

    /**
     * Delete a token from the storage.
     *
     * @param string $token The token to delete.
     * @param null|string $key The key under which to delete the token.
     * If null, the default token will be deleted.
     * @return void
     */
    public function deleteToken(string $token, ?string $key = null): void;

    /**
     * Atomically check and delete a token from the storage.
     * Returns true if the token was found and deleted, false otherwise.
     *
     * @param string $token The token to consume.
     * @param null|string $key The key under which to find the token.
     * If null, the default token will be consumed.
     * @return bool True if the token existed and was deleted, false otherwise.
     */
    public function consumeToken(string $token, ?string $key = null): bool;
}

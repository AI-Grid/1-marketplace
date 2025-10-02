# OpenSimulator UUID/Password Content Delivery Add-on

This repository provides a production-ready content delivery solution for OpenSimulator 9.3 consisting of:

- **`UuidPasswordContentDeliveryModule`** – a C# `ISharedRegionModule` that authenticates avatar UUID/password pairs, proxies asset delivery, and integrates with the bundled PHP web service.
- **PHP 8.2 web service** – exposes `/api/auth`, `/api/authorize`, and `/api/download` endpoints with strict validation, Argon2id password hashing, signed URLs, and rate limiting.
- **Infrastructure assets** – migrations, configuration samples, automated tests, and documentation.

## Repository Layout

```
opensim/                     # OpenSimulator module sources
  PhpApiClient.cs            # Internal HTTP client with retries/backoff
  UuidPasswordContentDeliveryModule.cs
php-app/                     # PHP backend application
  public/index.php           # Entry point/router
  src/                       # PHP services (Auth, Authorize, Validator, etc.)
  tests/                     # PHPUnit test suite
migrations/001_init.sql      # MySQL schema and seed scaffold
README.md                    # This document
```

## Building & Installing the OpenSim Module

1. Copy `opensim/UuidPasswordContentDeliveryModule.cs` and `opensim/PhpApiClient.cs` into your OpenSim source tree (e.g. `OpenSim/Region/OptionalModules/`).
2. Add the module name to your `OpenSim.ini`:

   ```ini
   [UuidPasswordContentDelivery]
   Enabled = true
   PhpApiBaseUrl = "https://content.example.com"
   SharedSecret = "CHANGE_ME"
   RequestTimeoutMs = 5000
   MaxRetries = 2
   ProxyBinary = false
   RateLimitBackoffMs = 500
   LoggingLevel = "INFO"
   ```

3. Rebuild OpenSim if required and restart the simulator. The module automatically registers `/content-delivery/auth-check` (health) and `/content-delivery/fetch` (content) handlers on each region.

> **Note:** The module targets .NET 6.0 as required by OpenSim 9.3 and respects multi-region deployments.

## Deploying the PHP Backend

1. Install dependencies:

   ```bash
   cd php-app
   composer install --no-dev --optimize-autoloader
   ```

2. Copy `.env.example` to `.env` and update the values:

   ```bash
   cp .env.example .env
   ```

   | Key | Description |
   | --- | --- |
   | `APP_BASE_URL` | Public HTTPS base URL (e.g. `https://content.example.com`). |
   | `DB_*` | MySQL DSN/credentials. |
   | `HMAC_SECRET` | Secret used to sign `/api/download` URLs. |
   | `SHARED_SECRET` | Shared module secret (must match OpenSim `SharedSecret`). |
   | `SIGNED_URL_TTL_SECONDS` | Signed URL lifetime (default 600s). |
   | `TOKEN_TTL_SECONDS` | Authentication token lifetime (default 600s). |
   | `RATE_LIMIT_PER_MINUTE` | Requests per minute per client. |
   | `DOWNLOAD_STRATEGY` | `signed_url` (default) or `inline`. |
   | `STORAGE_BASE_PATH` | Absolute path to on-disk asset store. |

3. Apply the migration to your MySQL instance:

   ```bash
   mysql -u opensim -p opensim < migrations/001_init.sql
   ```

4. Configure your web server (nginx/Apache) to route HTTPS requests to `php-app/public/index.php` via PHP-FPM.

5. Ensure TLS termination is active; the service rejects non-HTTPS requests when `FORCE_HTTPS=true`.

## End-to-End Flow

1. **Authenticate** – The module posts `{avatar_uuid, password}` to `/api/auth`. The PHP service validates credentials (Argon2id hashed passwords) and returns `{ok, token, expires_at}`.
2. **Authorize** – The module posts `{token, request, id}` to `/api/authorize` to request an asset, inventory listing, or package. A successful response contains either `binary` content (base64) or a signed download URL.
3. **Download** – When a signed URL is returned, the module either redirects the viewer or proxies the binary (configurable) by calling `/api/download?id=...&expires=...&sig=...`.

## Example cURL Invocations

```bash
curl -sS https://content.example.com/api/auth \
  -H 'Content-Type: application/json' \
  -d '{"avatar_uuid":"123e4567-e89b-12d3-a456-426614174000","password":"CorrectHorseBatteryStaple"}'

curl -sS https://content.example.com/api/authorize \
  -H 'Content-Type: application/json' \
  -d '{"token":"<token>","request":"asset","id":"123e4567-e89b-12d3-a456-426614174001"}'

curl -L "https://content.example.com/api/download?id=123e4567-e89b-12d3-a456-426614174001&expires=<ts>&sig=<sig>"
```

## Testing

Run the automated suites from the repository root:

```bash
# PHP unit tests
(cd php-app && composer install && ./vendor/bin/phpunit)

# .NET unit tests for PhpApiClient
(dotnet test tests/cs/UuidPasswordContentDeliveryModule.Tests.csproj)
```

Both suites provide coverage for request validation, token issuance, signed URL generation, and HTTP client retry logic.

## Security Considerations

- UUIDs are validated client- and server-side.
- Passwords are hashed with Argon2id; tokens are stored hashed and expire automatically.
- Signed URLs use HMAC-SHA256 with configurable TTL.
- PHP endpoints enforce per-client rate limiting and reject non-HTTPS requests in production.
- The OpenSim module performs exponential backoff and structured logging with correlation IDs.

## Maintenance

- Update dependencies via `composer update` and `dotnet restore` as needed.
- Rotate `HMAC_SECRET` periodically and sync with OpenSim configuration.
- Purge expired tokens with a scheduled job (`DELETE FROM auth_tokens WHERE expires_at < NOW()`).


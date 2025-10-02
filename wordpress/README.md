# OpenSim Marketplace

The OpenSim Marketplace plugin provides a WordPress-based storefront for grid operators. It imports in-world prim listings, processes avatar purchases against the MoneyServer database, and now delegates item delivery to an external PHP delivery management service.

## Requirements
- WordPress 6.0 or later with the plugin installed in `wp-content/plugins`
- PHP 8.0+
- Access to the OpenSim and MoneyServer MySQL databases
- A PHP delivery backend that exposes a `deliver` endpoint (see below)

## Configuration
Navigate to **Settings → OpenSim Marketplace** after activating the plugin.

### Delivery API
Configure the following settings so the plugin can talk to your PHP delivery backend:

- **PHP Delivery API Base URL** – Base URL to the management service. The plugin automatically calls the `/deliver` endpoint on this base for purchases and redeliveries (for example `https://delivery.example.com/api`).
- **Delivery API Shared Secret** – Secret shared between WordPress and the delivery backend. Every delivery request includes this value for verification.

Configure the backend to accept JSON payloads containing `buyer_uuid`, `asset_id`, and `shared_secret`, and to respond with JSON similar to:

```json
{
  "success": true,
  "message": "Item queued for delivery",
  "correlation_id": "abc123"
}
```

The correlation identifier is stored in the delivery logs so you can trace fulfilment in the external system.

### Database Connections
Provide OpenSim and MoneyServer connection details so the plugin can reconcile purchases and update balances. Passwords are encrypted before storage; leave the password fields blank to keep previously saved values.

## Delivery Flow
1. A buyer initiates a purchase from the marketplace UI or via the REST endpoint.
2. WordPress debits the buyer, records the order, and calls the PHP delivery API with the buyer UUID, asset UUID, and shared secret.
3. A successful API response marks the order as delivered, displays the success message to the buyer, and logs the returned correlation ID.
4. Failed API responses surface the error back to the buyer and keep the order in a failed state for redelivery.

Admin users can request redelivery from the Orders screen; the same PHP endpoint is called and its response is shown in the admin notice.

## Troubleshooting
- Ensure the base URL is reachable from the WordPress server and responds within 30 seconds.
- Check the WordPress debug log for entries beginning with “OpenSim Marketplace delivery error” for failures or “delivery correlation ID” for successful correlation IDs.
- Use the delivery logs table (`wp_market_delivery_logs`) to audit the status, message, and correlation identifier returned by the backend.

# Country-Aware DNS over HTTPS (DoH) Worker

A Cloudflare Worker that optimizes CDN routing by intelligently handling EDNS Client Subnet (ECS). It dual-resolves DNS queries using both the client's actual IP and an alternative IP (e.g., VPN exit IP) to select the best response, ensuring optimal performance and content availability.

[中文介绍](https://crzidea.com/#/article/introducing-crzidea-doh)

![DoH Architecture Diagram](https://www.plantuml.com/plantuml/png/bP7HRjCm58RlznI7NWs9sXfi876rAKLT9T95BTc4fgboujFMmh63VRokF3sEILKQxMQNFZxVdo-_hpq9Hw7HP--KgNMG25kYrd_bt8aTsoZQXYfuTBKrX8PORHlUQc4wPkn9QbNnx79STACo_yuRuGbT7AsoZdWXrdRff4WZrEwFaYYujDkpvJukDkVJcmymcYgw3HNSrAIiyQCu6Rq_BEHvFERY9LT6djva3_6OQHlaMWk7y63TBtG3F9kSBaqk-liYhbfpNiPJwT5rquczXKmhD7Jafnq_jNQZ8pjVzl02TJ9FSXSCYg0rJD7E2f22H2KymjhP1WxYHoG9VMHGjjeAEOJ8mgdi4Ko_-ud112Ev_x_BdXhqqADbJruoME3lW9uEBzoXp8TAsaOemtR_C2RncTUfXR5g-UDiMQncnTDXLDjWoEtvOtPNpdyiVgwokyct9ouqeJE2r3CcwhwO9qeQFuuVTVlUfbD9bLwzecCyswIcZnZi56qXEa1iAReQf67IvxSaHQzNazAhV65mBxIIWX0S-g09x1fS7twL4WOF5YEkqSZGwBy0)

## Features

- **Smart Routing**: Prioritizes local CDN nodes by checking if the resolved IP matches the client's country.
- **VPN Optimization**: Falls back to an alternative IP resolution if the local lookup fails to match the country, ensuring access through VPNs.
- **Privacy First**: Encrypts DNS queries via HTTPS, protecting against eavesdropping.
- **D1 Database**: Uses Cloudflare D1 for efficient Geolocation lookups.
- **IPv6 Support**: Full support for AAAA record parsing and IPv6 geolocation.
- **Multi-Level Caching**: L1 (Memory) + L2 (Cache API) for ultra-low latency.
- **Upstream Failover**: Automatic fallback between DNS upstreams (Cloudflare → Google).

## Data Source

This project uses **[Loyalsoldier/geoip](https://github.com/Loyalsoldier/geoip)** for IP geolocation data. No registration or API keys are required!

## Prerequisites

Before deploying, ensure you have:

- A [Cloudflare](https://dash.cloudflare.com/sign-up) account.
- A GitHub account.

## Deployment

This project uses **GitHub Actions** for automated deployment and initialization. You do not need to install any tools locally.

### 1. Fork the Repository

Fork this repository to your own GitHub account.

### 2. Configure Secrets

Go to your forked repository's **Settings** > **Secrets and variables** > **Actions**, and add the following **Repository secrets**:

| Secret Name             | Description                                                                                                                                 |
| :---------------------- | :------------------------------------------------------------------------------------------------------------------------------------------ |
| `CLOUDFLARE_API_TOKEN`  | Your Cloudflare API Token (Permissions: `Worker Scripts: Edit`, `D1: Edit`). [Get it here](https://dash.cloudflare.com/profile/api-tokens). |
| `CLOUDFLARE_ACCOUNT_ID` | Your Cloudflare Account ID. Found in the URL of your Cloudflare Dashboard.                                                                  |
| `UPSTREAM_ENDPOINT`     | (Optional) Custom primary upstream DoH server (Default: `https://1.1.1.1/dns-query`).                                                       |

### 3. Deploy

The deployment workflow acts automatically:

1. **Enable Workflows**: Go to the **Actions** tab in your repository and enable workflows if asked.
2. **Trigger Deployment**: The workflow runs automatically on every push to the `main` branch or weekly (Tuesday 10:30 UTC). You can also manually trigger it from the **Actions** tab by selecting the "Deploy" workflow and clicking **Run workflow**.

> **Automatic Setup**: The workflow will automatically download the GeoIP database from Loyalsoldier, create the D1 database, import the data (IPv4 & IPv6), and deploy the worker.

## Configuration

The worker is configured primarily through the **GitHub Secrets** defined above.

### Optional Environment Variables

These variables can be set in `wrangler.toml` or Cloudflare Dashboard to customize worker behavior:

| Variable             | Default             | Description                                  |
| :------------------- | :------------------ | :------------------------------------------- |
| `MEM_CACHE_MAX_SIZE` | `10000`             | Maximum entries in GeoIP memory cache        |
| `CACHE_TTL_SECONDS`  | `86400`             | GeoIP cache TTL in seconds (24 hours)        |
| `DEBUG`              | `false`             | Enable verbose logging (`true` to enable)    |
| `COUNTRY_PRIORITY`   | `CN,HK,TW,JP,SG,US` | Comma-separated country priority for routing |

**Example wrangler.toml:**

```toml
[vars]
MEM_CACHE_MAX_SIZE = "20000"
CACHE_TTL_SECONDS = "43200"
DEBUG = "true"
COUNTRY_PRIORITY = "CN,HK,TW,JP,SG,US"
```

## API Endpoints

### DoH Endpoint (RFC 8484)

`GET/POST https://<your-worker-domain>/?dns=<BASE64_DNS_QUERY>`

### JSON DNS API

```bash
GET https://<your-worker-domain>/resolve?name=example.com&type=A
```

Returns Google DNS JSON API compatible response.

### Health Check

```bash
GET https://<your-worker-domain>/health
```

### Statistics

```bash
GET https://<your-worker-domain>/stats
```

### IP Debug

```bash
GET https://<your-worker-domain>/debug/ip/8.8.8.8
```

## API Reference

The DoH endpoint accepts requests in the following format:

`https://<your-worker-domain>/client-ip/<IP>/client-country/<COUNTRY_CODE>/alternative-ip/<ALT_IP>/dns-query`

### Parameters

| Parameter        | Description                                                          | Required | Source Priority                      |
| :--------------- | :------------------------------------------------------------------- | :------- | :----------------------------------- |
| `client-ip`      | The client's real IP address.                                        | No       | URL Path > `CF-Connecting-IP` header |
| `client-country` | The 2-letter ISO country code of the client.                         | No       | URL Path > `CF-IPCountry` header     |
| `alternative-ip` | The IP address to use for the secondary resolution (e.g., VPN exit). | Yes      | URL Path                             |

### Example

```bash
curl "https://doh.subdomain.workers.dev/client-ip/223.5.5.5/client-country/CN/alternative-ip/8.8.8.8/dns-query?dns=<BASE64_DNS_QUERY>"
```

## Architecture

```text
┌─────────────┐     ┌──────────────────────────────────────────┐
│   Client    │────▶│           Cloudflare Worker              │
└─────────────┘     │                                          │
                    │  ┌────────────────────────────────────┐  │
                    │  │  Parallel DNS Queries              │  │
                    │  │  ┌──────────┐    ┌──────────────┐  │  │
                    │  │  │ Client IP│    │Alternative IP│  │  │
                    │  │  │   (ECS)  │    │    (ECS)     │  │  │
                    │  │  └────┬─────┘    └──────┬───────┘  │  │
                    │  └───────┼─────────────────┼──────────┘  │
                    │          ▼                 ▼              │
                    │  ┌───────────────────────────────────┐   │
                    │  │    Upstream (CF 1.1.1.1 / Google) │   │
                    │  └───────────────┬───────────────────┘   │
                    │                  ▼                       │
                    │  ┌───────────────────────────────────┐   │
                    │  │   IP → Country Lookup             │   │
                    │  │   ┌─────┐ ┌─────┐ ┌────┐          │   │
                    │  │   │ L1  │→│ L2  │→│ D1 │          │   │
                    │  │   │ Mem │ │Cache│ │ DB │          │   │
                    │  │   └─────┘ └─────┘ └────┘          │   │
                    │  └───────────────────────────────────┘   │
                    │                  ▼                       │
                    │  ┌───────────────────────────────────┐   │
                    │  │ Country Match? → Return Best IP   │   │
                    │  └───────────────────────────────────┘   │
                    └──────────────────────────────────────────┘
```

## Contributing

Contributions are welcome! Please feel free to open issues or submit pull requests.

# Cloudflare API coverage

Generated from `cloudflare/api-schemas@650bd71c22db3b938a4611bf4cc5afd896b400b7` (2026-11-07T06:07:05Z), file `openapi.json`, SHA-256 `f4a13c74ffc7e9108a1e8b459c39c5e405f659f6b5e5b9a5a284f9039620a40c`.

| | Count |
|---|---|
| Paths | 2352 |
| Operations | 3777 |
| GET | 1848 |
| POST | 798 |
| PUT | 367 |
| PATCH | 275 |
| DELETE | 489 |
| Schemas | 6990 |
| Generated C# files | 25720 |

Every operation listed in the schema is reachable through `ICloudflareClient.OpenApi`.

## Normalization

Rules are described in [normalization.md](normalization.md).

| Rule | Applied |
|---|---|
| P1 indexer-renamed | 1 |
| R1 enum-with-empty-value | 11 |
| R10 overridden-property-default-dropped | 71 |
| R2 untyped-object | 61 |
| R3a single-ref-allOf-unwrapped | 892 |
| R3b non-inheritable-base-dropped | 19 |
| R4 primitive-allOf-collapsed | 93 |
| R5 nested-union-flattened | 22 |
| R6 untyped-object-union | 335 |
| R7 untyped-union-member | 28 |
| R8 wildcard-path-segment | 4 |
| R9 reference-alias-removed | 121 |

## Operations per area

| Area | Operations |
|---|---|
| `/accounts/{id}/cloudforce-one` | 299 |
| `/radar` | 279 |
| `/accounts/{id}/magic` | 144 |
| `/accounts/{id}/access` | 142 |
| `/accounts/{id}/workers` | 140 |
| `/accounts/{id}/dlp` | 108 |
| `/accounts/{id}/email-security` | 75 |
| `/accounts/{id}/devices` | 74 |
| `/accounts/{id}/ai-gateway` | 67 |
| `/accounts/{id}/realtime` | 63 |
| `/zones/{id}/settings` | 58 |
| `/accounts/{id}/gateway` | 57 |
| `/accounts/{id}/cws` | 54 |
| `/accounts/{id}/ai-search` | 49 |
| `/accounts/{id}/stream` | 49 |
| `/zones/{id}/access` | 44 |
| `/zones/{id}/api_gateway` | 44 |
| `/accounts/{id}/data-security` | 42 |
| `/accounts/{id}/addressing` | 41 |
| `/zones/{id}/firewall` | 40 |
| `/accounts/{id}/brand-protection` | 39 |
| `/zones/{id}/email` | 38 |
| `/accounts/{id}/builds` | 37 |
| `/accounts/{id}/load_balancers` | 36 |
| `/accounts/{id}/r2` | 36 |
| `/accounts/{id}/images` | 35 |
| `/accounts/{id}/intel` | 35 |
| `/accounts/{id}/dex` | 34 |
| `/accounts/{id}/email` | 32 |
| `/accounts/{id}/browser-rendering` | 27 |
| `/accounts/{id}/workflows` | 27 |
| `/accounts/{id}/alerting` | 25 |
| `/accounts/{id}/vectorize` | 24 |
| `/accounts/{id}/pages` | 23 |
| `/accounts/{id}/queues` | 23 |
| `/zones/{id}/cache` | 23 |
| `/zones/{id}/waiting_rooms` | 23 |
| `/accounts/{id}/vuln_scanner` | 22 |
| `/accounts/{id}/logpush` | 20 |
| `/accounts/{id}/shares` | 20 |
| `/accounts/{id}/artifacts` | 19 |
| `/accounts/{id}/pipelines` | 19 |
| `/accounts/{id}/billing` | 18 |
| `/accounts/{id}/security-center` | 18 |
| `/accounts/{id}/iam` | 17 |
| `/accounts/{id}/scim` | 17 |
| `/accounts/{id}/basin-catalog` | 16 |
| `/accounts/{id}/cni` | 16 |
| `/accounts/{id}/containers` | 16 |
| `/accounts/{id}/logs` | 16 |
| `/accounts/{id}/mnm` | 16 |
| `/accounts/{id}/r2-catalog` | 16 |
| `/accounts/{id}/rulesets` | 16 |
| `/accounts/{id}/zerotrust` | 16 |
| `/zones/{id}/rulesets` | 16 |
| `/accounts/{id}/ai` | 15 |
| `/accounts/{id}/flagship` | 15 |
| `/accounts/{id}/secondary_dns` | 15 |
| `/zones/{id}/schema_validation` | 15 |
| `/zones/{id}/security-center` | 15 |
| `/zones/{id}/token_validation` | 15 |
| `/accounts/{id}/agent-memory` | 14 |
| `/accounts/{id}/storage` | 14 |
| `/accounts/{id}/teamnet` | 14 |
| `/accounts/{id}/urlscanner` | 14 |
| `/zones/{id}/dns_records` | 14 |
| `/zones/{id}/logpush` | 14 |
| `/accounts/{id}/d1` | 13 |
| `/accounts/{id}/pay-per-crawl` | 13 |
| `/accounts/{id}/registrar` | 13 |
| `/accounts/{id}/rum` | 13 |
| `/zones/{id}/logs` | 13 |
| `/zones/{id}/origin_tls_client_auth` | 13 |
| `/zones/{id}/page_shield` | 13 |
| `/zones/{id}/secondary_dns` | 13 |
| `/accounts/{id}/cfd_tunnel` | 12 |
| `/accounts/{id}/dns_settings` | 12 |
| `/accounts/{id}/secrets_store` | 12 |
| `/accounts/{id}/slurper` | 12 |
| `/user` | 12 |
| `/zones/{id}/ssl` | 12 |
| `/zones/{id}/web3` | 12 |
| `/accounts/{id}/one` | 11 |
| `/accounts/{id}/rules` | 11 |
| `/accounts/{id}/warp_connector` | 11 |
| `/accounts/{id}/zt_risk_scoring` | 11 |
| `/zones/{id}/custom_hostnames` | 11 |
| `/accounts/{id}/abuse-reports` | 10 |
| `/accounts/{id}/calls` | 10 |
| `/accounts/{id}/registrar-sandbox` | 10 |
| `/user/{id}/pools` | 10 |
| `/zones/{id}/smart_shield` | 10 |
| `/zones/{id}/speed_api` | 10 |
| `/accounts/{id}/analytics` | 9 |
| `/accounts/{id}/custom_pages` | 9 |
| `/accounts/{id}/dns_firewall` | 9 |
| `/accounts/{id}/infrastructure` | 9 |
| `/accounts/{id}/managed-defense` | 9 |
| `/accounts/{id}/pay-per-use` | 9 |
| `/accounts/{id}/pcaps` | 9 |
| `/accounts/{id}/subscriptions` | 9 |
| `/zones/{id}/custom_pages` | 9 |
| `/zones/{id}/healthchecks` | 9 |
| `/zones/{id}/spectrum` | 9 |
| `/accounts/{id}/browser-extension` | 8 |
| `/accounts/{id}/firewall` | 8 |
| `/accounts/{id}/hyperdrive` | 8 |
| `/accounts/{id}/moq` | 8 |
| `/accounts/{id}/resource-library` | 8 |
| `/accounts/{id}/tokens` | 8 |
| `/subscriptions` | 8 |
| `/user/{id}/monitors` | 8 |
| `/zones/{id}/content-upload-scan` | 8 |
| `/zones/{id}/environments` | 8 |
| `/zones/{id}/monetization` | 8 |
| `/zones/{id}/snippets` | 8 |
| `/accounts/{id}/autorag` | 7 |
| `/accounts/{id}/dls` | 7 |
| `/accounts/{id}/oauth_clients` | 7 |
| `/accounts/{id}/tags` | 7 |
| `/cws` | 7 |
| `/zones/{id}/filters` | 7 |
| `/zones/{id}/leaked-credential-checks` | 7 |
| `/zones/{id}/origin` | 7 |
| `/zones/{id}/pagerules` | 7 |
| `/zones/{id}/pay-per-use` | 7 |
| `/accounts/{id}/challenges` | 6 |
| `/accounts/{id}/diagnostics` | 6 |
| `/accounts/{id}/k2` | 6 |
| `/accounts/{id}/payment-methods` | 6 |
| `/accounts/{id}/reporting` | 6 |
| `/accounts/{id}/sso_connectors` | 6 |
| `/zones/{id}/acm` | 6 |
| `/zones/{id}/custom_certificates` | 6 |
| `/zones/{id}/load_balancers` | 6 |
| `/zones/{id}/observability` | 6 |
| `/accounts` | 5 |
| `/accounts/{id}/connectivity` | 5 |
| `/accounts/{id}/event_subscriptions` | 5 |
| `/accounts/{id}/members` | 5 |
| `/accounts/{id}/mtls_certificates` | 5 |
| `/organizations` | 5 |
| `/user/{id}/access_rules` | 5 |
| `/zones` | 5 |
| `/zones/{id}/addressing` | 5 |
| `/zones/{id}/client_certificates` | 5 |
| `/zones/{id}/keyless_certificates` | 5 |
| `/zones/{id}/rate_limits` | 5 |
| `/zones/{id}/workers` | 5 |
| `/accounts/{id}/botnet_feed` | 4 |
| `/accounts/{id}/custom_csrs` | 4 |
| `/accounts/{id}/event_notifications` | 4 |
| `/accounts/{id}/triggers` | 4 |
| `/certificates` | 4 |
| `/memberships` | 4 |
| `/organizations/{id}/members` | 4 |
| `/tenants` | 4 |
| `/user/{id}/{token_id}` | 4 |
| `/zones/{id}/ai-security` | 4 |
| `/zones/{id}/analytics` | 4 |
| `/zones/{id}/argo` | 4 |
| `/zones/{id}/bot_management` | 4 |
| `/zones/{id}/custom_csrs` | 4 |
| `/zones/{id}/dnssec` | 4 |
| `/zones/{id}/hold` | 4 |
| `/zones/{id}/hostnames` | 4 |
| `/zones/{id}/intel` | 4 |
| `/zones/{id}/pay-per-crawl` | 4 |
| `/zones/{id}/subscription` | 4 |
| `/accounts/{id}/billable` | 3 |
| `/accounts/{id}/custom_ns` | 3 |
| `/accounts/{id}/field_extractors` | 3 |
| `/accounts/{id}/settings` | 3 |
| `/analytics` | 3 |
| `/pages` | 3 |
| `/v2` | 3 |
| `/zones/{id}/managed_headers` | 3 |
| `/zones/{id}/subscriptions` | 3 |
| `/zones/{id}/tags` | 3 |
| `/zones/{id}/url_normalization` | 3 |
| `/accounts/{id}/analytics_engine` | 2 |
| `/accounts/{id}/billable-usage` | 2 |
| `/accounts/{id}/monetization` | 2 |
| `/accounts/{id}/profile` | 2 |
| `/accounts/{id}/roles` | 2 |
| `/billing` | 2 |
| `/organizations/{id}/logs` | 2 |
| `/organizations/{id}/profile` | 2 |
| `/user/{id}/{invite_id}` | 2 |
| `/user/{id}/{organization_id}` | 2 |
| `/user/{id}/{identifier}` | 2 |
| `/zones/{id}/ai-audit` | 2 |
| `/zones/{id}/available_plans` | 2 |
| `/zones/{id}/certificate_authorities` | 2 |
| `/zones/{id}/cloud_connector` | 2 |
| `/zones/{id}/ct` | 2 |
| `/zones/{id}/custom_ns` | 2 |
| `/zones/{id}/devices` | 2 |
| `/zones/{id}/dns_analytics` | 2 |
| `/zones/{id}/dns_settings` | 2 |
| `/zones/{id}/fraud_detection` | 2 |
| `/zones/{id}/images` | 2 |
| `/zones/{id}/precursor` | 2 |
| `/_heartbeat` | 1 |
| `/accounts/{id}/argo` | 1 |
| `/accounts/{id}/audit_logs` | 1 |
| `/accounts/{id}/bulk` | 1 |
| `/accounts/{id}/client-secret` | 1 |
| `/accounts/{id}/dns_records` | 1 |
| `/accounts/{id}/entitlements` | 1 |
| `/accounts/{id}/invoices` | 1 |
| `/accounts/{id}/media` | 1 |
| `/accounts/{id}/move` | 1 |
| `/accounts/{id}/observability` | 1 |
| `/accounts/{id}/organizations` | 1 |
| `/accounts/{id}/pay-invoice` | 1 |
| `/accounts/{id}/receipts` | 1 |
| `/accounts/{id}/request-tracer` | 1 |
| `/accounts/{id}/tunnels` | 1 |
| `/accounts/{id}/waiting_rooms` | 1 |
| `/internal` | 1 |
| `/ips` | 1 |
| `/live` | 1 |
| `/oauth` | 1 |
| `/organizations/{id}/accounts` | 1 |
| `/organizations/{id}/billable` | 1 |
| `/organizations/{id}/invites` | 1 |
| `/organizations/{id}/members:batchCreate` | 1 |
| `/organizations/{id}/shares` | 1 |
| `/produce` | 1 |
| `/ready` | 1 |
| `/signed-url` | 1 |
| `/user/{id}/dashboard` | 1 |
| `/user/{id}/count_zones_enabled` | 1 |
| `/user/{id}/history` | 1 |
| `/user/{id}/profile` | 1 |
| `/user/{id}/preview` | 1 |
| `/user/{id}/regions` | 1 |
| `/user/{id}/events` | 1 |
| `/user/{id}/{membership_id}` | 1 |
| `/user/{id}/zones` | 1 |
| `/user/{id}/permission_groups` | 1 |
| `/user/{id}/verify` | 1 |
| `/v1` | 1 |
| `/workers` | 1 |
| `/zones/{id}/activation_check` | 1 |
| `/zones/{id}/available_rate_plans` | 1 |
| `/zones/{id}/dcv_delegation` | 1 |
| `/zones/{id}/entitlements` | 1 |
| `/zones/{id}/invalidate_cache` | 1 |
| `/zones/{id}/media` | 1 |
| `/zones/{id}/purge_cache` | 1 |
| `/zones/{id}/rate_limit_analytics` | 1 |
| `/zones/{id}/stream` | 1 |

# Blockmerge

`blockmerge` retrieves configured IP blocklists, merges them, and writes inbound and outbound outputs. All binaries default to `blockmerge.toml`; `blockmerge-web` reads its optional `[web]` section from that same file.

## Containers

Build all container variants locally with Docker Buildx:

```bash
docker buildx bake --load
```

All Bake targets are `linux/amd64`. This command also works on Apple Silicon through Buildx emulation. Build a subset with `docker buildx bake debian --load`, `docker buildx bake alpine --load`, or an individual target such as `docker buildx bake cli-alpine --load`.

The resulting images are:

| Image | Purpose |
| --- | --- |
| `blockmerge:debian` | Scheduled file-writing daemon on Debian |
| `blockmerge:alpine` | Scheduled file-writing daemon on Alpine |
| `blockmerge-web:debian` | HTTP server on Debian |
| `blockmerge-web:alpine` | HTTP server on Alpine |

Container processes run as UID/GID `10001`. On Linux, ensure bind-mounted writable directories belong to that user before starting a container:

```bash
mkdir -p data output public
sudo chown -R 10001:10001 data output public
```

Run the scheduled daemon, which writes generated lists to the local `output` directory and preserves refresh state in `data`:

```bash
docker run --detach --name blockmerge \
  --volume "$PWD/blockmerge.toml:/app/config/blockmerge.toml:ro" \
  --volume "$PWD/data:/app/data" \
  --volume "$PWD/output:/app/output" \
  blockmerge:debian
```

The daemon is the default command. Supply any `blockmerge` argument to replace `--daemon` and perform a one-shot run; for example:

```bash
docker run --rm \
  --volume "$PWD/blockmerge.toml:/app/config/blockmerge.toml:ro" \
  --volume "$PWD/data:/app/data" \
  --volume "$PWD/output:/app/output" \
  blockmerge:alpine --config /app/config/blockmerge.toml
```

Run the web server and persist both its refresh data and generated public assets:

```bash
docker run --detach --name blockmerge-web --publish 8080:8080 \
  --volume "$PWD/blockmerge.toml:/app/config/blockmerge.toml:ro" \
  --volume "$PWD/data:/app/data" \
  --volume "$PWD/public:/app/public" \
  blockmerge-web:alpine
```

The web image serves `/app/public` on port 8080. If the `[web]` configuration selects another root directory, mount that path instead and ensure it is writable by UID/GID `10001`.

## Scheduled daemon

Run `blockmerge --daemon` to refresh blocklists continuously using the required `[schedule]` section. It honors `run_on_startup`, accepts either `interval` or `cron`, retains the configured refresh state/cache between runs, and exits cleanly on Ctrl-C or SIGTERM.

The default one-shot command writes `blocklist_output_inbound.txt` and `blocklist_output_outbound.txt`. Set `--inbound-output` / `BLOCKMERGE_INBOUND_OUTPUT` and `--outbound-output` / `BLOCKMERGE_OUTBOUND_OUTPUT` to choose independent paths. This is useful when mounting files from a container.

Generated output has a `# Blockmerge updated at ...` UTC timestamp header by default. Configure it with:

```toml
[output]
timestamp_header = true # set false for CIDR-only output
```

Blockmerge compares generated CIDR content with the existing file, ignoring that header. Unchanged directional lists are not rewritten, so their timestamp records the last actual list-content update.

### Large-list memory validation

An ignored release-mode test exercises parsing, merging, rendering, and writing 4,228,762 deterministic IPv4 entries. On Linux, it reads its own peak resident memory from `/proc/self/status` and verifies that it remains below 512 MiB:

```bash
cargo test --release \
  source::tests::processes_4_2m_entries_under_512_memory_budget \
  -- --ignored --exact --nocapture
```

The expected maximum resident set size is below the 512 MiB memory budget.

## Offline snapshots

Run `blockmerge-download-raw --output-dir <directory>` to save raw source bodies and write a `manifest.json`. The manifest is a required versioned JSON document whose entries include a relative filename, source URL when applicable, SHA-256 checksum, and download timestamp. `blockmerge-offline-generate` verifies every checksum before parsing the saved bodies with the current `blockmerge.toml` rules.

Legacy array-shaped manifests are unsupported. Regenerate them with `blockmerge-download-raw`.

## Resilient refreshes

Network sources use a last-known-good raw-body cache by default. After a fetch failure, Blockmerge uses a verified cached body only while it is younger than `max_stale_age` and has fewer than `max_consecutive_failures` consecutive failures. The defaults are 24 hours and four failures; override them in `[resilience]` or set `enabled = false` to disable fallback.

Cached HTTP sources automatically use `ETag` and `Last-Modified` validators when provided by the server. An unchanged response reuses the checksum-verified cached body instead of downloading it again. Conditional requests require resilience and are disabled when `enabled = false`; normal-source fallback is disabled as before, while GeoIP retains its independent scheduled snapshot behavior. No per-source opt-in is required.

State and cached bodies use native per-user application directories through `etcetera`. Override them for containers or services with `--state-file` / `BLOCKMERGE_STATE_FILE` and `--cache-dir` / `BLOCKMERGE_CACHE_DIR`; command-line values take precedence over environment variables. In the container, mount the selected paths when refresh state must survive replacement.

## GeoIP country blocks

Configure a supported GeoIP service as an optional source. The database is downloaded no more often than every 24 hours and the last verified snapshot is retained indefinitely while the source remains enabled. Normal blocklist refreshes continue to use that snapshot between GeoIP downloads; allowlists still take precedence over country blocks.

IPLocate is package-owned: Blockmerge selects its supported endpoint, ZIP/CSV format, and `apikey` query parameter.

```toml
[geoip]
name = "geoip"
service = "iplocate"
refresh_interval = "24h"
api_key_env = "IPLOCATE_API_KEY"
# api_key = "optional-inline-fallback"

[[geoip.country_rules]]
country_codes = ["RU", "CN"]
direction = "inbound"

[[geoip.country_rules]]
country_codes = ["IR"]
direction = "both"
```

Use a custom service when it provides a CSV or ZIP-compressed CSV with network and country-code columns:

```toml
[geoip]
service = "custom"
refresh_interval = "24h"
api_key_env = "CUSTOM_GEOIP_KEY"

[geoip.custom]
download_url = "https://provider.example/ip-to-country.csv.zip"
format = "zip_csv" # or "csv"
network_column = "network"          # defaults to "network"
country_code_column = "country_code" # defaults to "country_code"
api_key_query_parameter = "apikey"   # omit for unauthenticated downloads
```

`refresh_interval` cannot be shorter than 24 hours. If an eligible GeoIP download fails, Blockmerge retains the previous verified snapshot and retries on the next eligible daily attempt. If no snapshot exists yet, it writes outputs from the other configured sources. `blockmerge-download-raw` is an explicit manual snapshot command and downloads GeoIP immediately.

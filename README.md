# Steam Headless

Containerized Steam with gamescope for remote gaming via Steam Remote Play.

## Requirements

- Docker with NVIDIA runtime
- NVIDIA GPU

## Quick start

First run — opens a visible desktop session to log into Steam:

```bash
./launch -b sdl -s desktop
```

After that, run headless for Remote Play:

```bash
./launch
```

Run `./launch --help` for all options.

## Local configuration

The launch script loads compose files in the following order:

- `docker-compose.yaml` — base configuration (always loaded)
- `docker-compose.ports.yaml` — default port forwarding
- `docker-compose.local.yaml` — optional, additive customizations (extra volumes, env vars, etc.)

If `docker-compose.local-override.yaml` exists, it replaces both `ports` and `local` entirely. Use this for advanced networking like macvlan where port forwarding isn't needed.

### Adding extra volumes or settings

Create a `docker-compose.local.yaml`:

```yaml
services:
  steam-gamescope:
    volumes:
      - /path/to/games:/home/steam/libraries/games:rw
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

See [ATTRIBUTIONS](ATTRIBUTIONS.md) for third-party credits.

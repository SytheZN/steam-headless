# Steam Headless

Containerized Steam with gamescope for remote gaming via Steam Remote Play.

## Requirements

- Docker with NVIDIA runtime
- NVIDIA GPU

## Usage

```bash
docker compose up --build
```

or to jump straight into nested desktop mode:
```bash
GAMESCOPE_BACKEND=sdl DEFAULT_SESSION=desktop docker compose up
```

## Configuration

Environment variables:
- `GAMESCOPE_BACKEND`: `sdl` for local testing, `headless` for remote (default: headless)
- `DEFAULT_SESSION`: `steam`, `desktop`, or `shell` (default: steam)

## Notes

- Custom gamescope build with NVIDIA fixes and input emulation
- Logs: `docker compose logs -f`

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

See [ATTRIBUTIONS](ATTRIBUTIONS.md) for third-party credits.

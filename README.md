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

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

See [ATTRIBUTIONS](ATTRIBUTIONS.md) for third-party credits.

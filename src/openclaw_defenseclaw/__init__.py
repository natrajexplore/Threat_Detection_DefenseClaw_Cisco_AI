"""DefenseClaw x OpenClaw NetOps security lab tooling."""


def main() -> None:
    from .cli import main as cli_main

    raise SystemExit(cli_main())

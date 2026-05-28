"""Pydantic-backed Config loading for small CLIs and scripts.

Config values use this precedence:

    code defaults < .env file < shell environment < CLI flags

Any field may hold a raw value or an `op://...` reference. Mark truly sensitive
fields with `secret=True` so snapshots redact them after references are resolved.
"""

from __future__ import annotations

import argparse
import os
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from types import UnionType
from typing import Any, Final, Literal, TypeVar, Union, cast, get_args, get_origin

from dotenv import dotenv_values
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from pydantic.config import JsonDict
from pydantic.fields import FieldInfo

from src_py_lib.clients.one_password import (
    OnePasswordClient,
    OnePasswordError,
    resolve_op_secret_ref,
)

DEFAULT_CONFIG_ENV_FILE: Final[Path] = Path(".env")
CONFIG_HELP_MIN_POSITION: Final[int] = 24
CONFIG_HELP_MAX_POSITION_LIMIT: Final[int] = 48
CONFIG_HELP_PADDING: Final[int] = 4
_CONFIG_OPTION_KEY: Final[str] = "src_py_lib_config_option"
_MISSING: Final[object] = object()


class ConfigHelpFormatter(argparse.RawTextHelpFormatter):
    """Help formatter for Config-backed CLIs."""

    def __init__(
        self,
        prog: str,
        indent_increment: int = 2,
        max_help_position: int = CONFIG_HELP_MIN_POSITION,
        width: int | None = None,
    ) -> None:
        super().__init__(prog, indent_increment, max_help_position, width)


class ConfigError(RuntimeError):
    """Raised when Config loading, validation, or reference resolution fails."""


@dataclass(frozen=True)
class ConfigOption:
    """Environment and CLI metadata for one Config field."""

    field_name: str
    env_var: str
    cli_flag: str = ""
    cli_aliases: tuple[str, ...] = ()
    cli_action: Literal["auto", "store_true", "store_false"] = "auto"
    cli_nargs: str | int | None = None
    cli_const: object | None = None
    metavar: str | None = None
    help: str = ""
    secret: bool = False
    required: bool = False


class Config(BaseModel):
    """Base class for project-specific Pydantic Config models."""

    model_config = ConfigDict(extra="forbid")


ConfigType = TypeVar("ConfigType", bound=Config)


def config_field(
    *,
    default: Any = ...,
    env_var: str,
    cli_flag: str | None = None,
    cli_aliases: Sequence[str] = (),
    cli_action: Literal["auto", "store_true", "store_false"] = "auto",
    cli_nargs: str | int | None = None,
    cli_const: object | None = None,
    metavar: str | None = None,
    help: str = "",
    secret: bool = False,
    required: bool = False,
    gt: int | float | None = None,
    ge: int | float | None = None,
    lt: int | float | None = None,
    le: int | float | None = None,
    pattern: str | None = None,
) -> Any:
    """Return a Pydantic field with Config environment and CLI metadata."""
    option = ConfigOption(
        field_name="",
        env_var=env_var,
        cli_flag=cli_flag or "",
        cli_aliases=tuple(cli_aliases),
        cli_action=cli_action,
        cli_nargs=cli_nargs,
        cli_const=cli_const,
        metavar=metavar,
        help=help,
        secret=secret,
        required=required,
    )
    field_kwargs: dict[str, Any] = {
        "description": help or None,
        "json_schema_extra": cast(JsonDict, {_CONFIG_OPTION_KEY: _config_option_payload(option)}),
    }
    if gt is not None:
        field_kwargs["gt"] = gt
    if ge is not None:
        field_kwargs["ge"] = ge
    if lt is not None:
        field_kwargs["lt"] = lt
    if le is not None:
        field_kwargs["le"] = le
    if pattern is not None:
        field_kwargs["pattern"] = pattern
    return Field(default, **field_kwargs)


def config_options(config_cls: type[Config]) -> tuple[ConfigOption, ...]:
    """Return all Config-backed fields declared on `config_cls`."""
    options: list[ConfigOption] = []
    for field_name, field_info in config_cls.model_fields.items():
        option = _config_option_from_field(field_name, field_info)
        if option is not None:
            options.append(option)
    return tuple(options)


def load_config_env_file(path: Path | None) -> dict[str, str]:
    """Load key/value pairs from a `.env` file.

    Missing files are ignored. Bare keys without `=` are ignored.
    """
    if path is None or not path.exists():
        return {}
    return {key: value for key, value in dotenv_values(path).items() if value is not None}


def load_config(
    config_cls: type[ConfigType],
    *,
    env_file: Path | None = DEFAULT_CONFIG_ENV_FILE,
    cli_overrides: Mapping[str, object] | None = None,
    env: Mapping[str, str] | None = None,
    base_dir: Path | None = None,
    resolve_op_refs: bool = False,
    op_client: OnePasswordClient | None = None,
    require: Iterable[str] = (),
) -> ConfigType:
    """Load, merge, and validate a Config model."""
    base = Path.cwd() if base_dir is None else base_dir
    resolved_env_file = _path_for_source(env_file, base) if env_file is not None else None
    env_file_values = load_config_env_file(resolved_env_file)
    shell_values = os.environ if env is None else env
    override_values = cli_overrides or {}

    values: dict[str, object] = {}
    for option in config_options(config_cls):
        raw = _selected_raw_value(option, env_file_values, shell_values, override_values)
        if raw is not _MISSING:
            if resolve_op_refs:
                raw = _resolve_source_ref(option, raw, client=op_client)
            field_info = config_cls.model_fields[option.field_name]
            values[option.field_name] = _prepare_source_value(raw, field_info.annotation, base)

    try:
        config = config_cls.model_validate(values)
    except ValidationError as exception:
        raise ConfigError(f"Invalid Config: {exception}") from exception

    required = tuple(option.field_name for option in config_options(config_cls) if option.required)
    require_config_values(config, (*required, *tuple(require)))
    return config


def add_config_arguments(
    parser: argparse.ArgumentParser,
    config_cls: type[Config],
    *,
    include_env_file: bool = True,
) -> None:
    """Add Config CLI flags to an argparse parser."""
    group = parser.add_argument_group(
        "Config",
        "These options override matching environment variables and .env values",
    )
    if include_env_file:
        group.add_argument(
            "--env-file",
            dest="env_file",
            default=None,
            metavar="PATH",
            help="Read Config .env values from PATH (default: .env)",
        )

    for option in config_options(config_cls):
        field_info = config_cls.model_fields[option.field_name]
        argument_kwargs: dict[str, Any] = {
            "dest": option.field_name,
            "default": None,
            "help": option.help,
        }
        if option.metavar is not None:
            argument_kwargs["metavar"] = option.metavar
        if option.cli_nargs is not None:
            argument_kwargs["nargs"] = option.cli_nargs
        if option.cli_const is not None:
            argument_kwargs["const"] = option.cli_const
        if _is_bool_annotation(field_info.annotation):
            if option.cli_action == "auto":
                argument_kwargs["action"] = argparse.BooleanOptionalAction
            else:
                argument_kwargs["action"] = option.cli_action
        group.add_argument(option.cli_flag, *option.cli_aliases, **argument_kwargs)


def config_parse_args(
    config_cls: type[ConfigType],
    *,
    parser: argparse.ArgumentParser | None = None,
    argv: Sequence[str] | None = None,
    description: str | None = None,
    include_env_file: bool = True,
    env: Mapping[str, str] | None = None,
    base_dir: Path | None = None,
    resolve_op_refs: bool = True,
    op_client: OnePasswordClient | None = None,
    require: Iterable[str] = (),
) -> ConfigType:
    """Parse Config CLI flags and return a validated Config model."""
    max_help_position = _config_help_max_position(config_cls, include_env_file=include_env_file)
    argument_parser = parser or argparse.ArgumentParser(
        description=description,
        formatter_class=_config_help_formatter(max_help_position),
    )
    add_config_arguments(argument_parser, config_cls, include_env_file=include_env_file)
    args = argument_parser.parse_args(argv)
    try:
        return load_config_from_args(
            config_cls,
            args,
            env=env,
            base_dir=base_dir,
            resolve_op_refs=resolve_op_refs,
            op_client=op_client,
            require=require,
        )
    except ConfigError as exception:
        argument_parser.error(str(exception))


def _config_help_formatter(max_help_position: int) -> type[argparse.HelpFormatter]:
    """Return a formatter class with this parser's computed help position."""

    class DynamicConfigHelpFormatter(ConfigHelpFormatter):
        def __init__(self, prog: str) -> None:
            super().__init__(prog, max_help_position=max_help_position)

    return DynamicConfigHelpFormatter


def _config_help_max_position(
    config_cls: type[Config],
    *,
    include_env_file: bool,
) -> int:
    """Return help-column width based on this Config's CLI arguments."""
    invocation_lengths = [len("--env-file PATH")] if include_env_file else []
    invocation_lengths.extend(
        _config_option_invocation_length(config_cls, option)
        for option in config_options(config_cls)
    )
    longest_invocation = max(invocation_lengths, default=0)
    return min(
        max(CONFIG_HELP_MIN_POSITION, longest_invocation + CONFIG_HELP_PADDING),
        CONFIG_HELP_MAX_POSITION_LIMIT,
    )


def _config_option_invocation_length(config_cls: type[Config], option: ConfigOption) -> int:
    """Return argparse-style option invocation length for help alignment."""
    field_info = config_cls.model_fields[option.field_name]
    option_strings = _config_option_strings(option, field_info)
    if _config_option_takes_value(option, field_info):
        arguments = _config_option_arguments(option)
        return len(", ".join(f"{option_string} {arguments}" for option_string in option_strings))
    return len(", ".join(option_strings))


def _config_option_strings(option: ConfigOption, field_info: FieldInfo) -> tuple[str, ...]:
    """Return option strings as argparse will display them."""
    if _is_bool_annotation(field_info.annotation) and option.cli_action == "auto":
        long_options = tuple(
            f"--no-{option_string.removeprefix('--')}"
            for option_string in (option.cli_flag, *option.cli_aliases)
            if option_string.startswith("--")
        )
        return (option.cli_flag, *long_options, *option.cli_aliases)
    return (option.cli_flag, *option.cli_aliases)


def _config_option_takes_value(option: ConfigOption, field_info: FieldInfo) -> bool:
    """Return whether argparse displays a value placeholder for this option."""
    if not _is_bool_annotation(field_info.annotation):
        return True
    return option.cli_action == "auto" and option.cli_nargs is not None


def _config_option_arguments(option: ConfigOption) -> str:
    """Return the argparse-style value placeholder for this option."""
    metavar = option.metavar or option.field_name.upper()
    if option.cli_nargs == "?":
        return f"[{metavar}]"
    if option.cli_nargs == "*":
        return f"[{metavar} ...]"
    if option.cli_nargs == "+":
        return f"{metavar} [{metavar} ...]"
    if isinstance(option.cli_nargs, int):
        return " ".join(metavar for _ in range(option.cli_nargs))
    return metavar


def config_overrides_from_args(
    config_cls: type[Config], args: argparse.Namespace
) -> dict[str, object]:
    """Return Config CLI overrides from parsed argparse args."""
    overrides: dict[str, object] = {}
    for option in config_options(config_cls):
        value = getattr(args, option.field_name, None)
        if value is not None:
            overrides[option.field_name] = value
    return overrides


def config_env_file_from_args(args: argparse.Namespace, *, attr: str = "env_file") -> Path | None:
    """Return the Config `.env` path from parsed argparse args, when supplied."""
    value = getattr(args, attr, None)
    return Path(cast(str, value)).expanduser() if value else None


def load_config_from_args(
    config_cls: type[ConfigType],
    args: argparse.Namespace,
    *,
    env: Mapping[str, str] | None = None,
    base_dir: Path | None = None,
    resolve_op_refs: bool = True,
    op_client: OnePasswordClient | None = None,
    require: Iterable[str] = (),
) -> ConfigType:
    """Load Config using argparse values produced by `add_config_arguments`.

    Secret references are resolved by default because CLI entrypoints usually need
    ready-to-use Config values.
    """
    return load_config(
        config_cls,
        env_file=config_env_file_from_args(args) or DEFAULT_CONFIG_ENV_FILE,
        cli_overrides=config_overrides_from_args(config_cls, args),
        env=env,
        base_dir=base_dir,
        resolve_op_refs=resolve_op_refs,
        op_client=op_client,
        require=require,
    )


def require_config_values(config: Config, fields: Iterable[str]) -> None:
    """Raise when any named Config field or environment variable is missing."""
    missing: list[str] = []
    options = config_options(type(config))
    for name in dict.fromkeys(fields):
        option = _option_by_name(options, name)
        value = getattr(config, option.field_name)
        if _value_is_missing(value):
            missing.append(option.env_var)
    if missing:
        raise ConfigError("Missing required Config value(s): " + ", ".join(missing))


def resolve_config_refs(
    config: ConfigType,
    *,
    fields: Iterable[str] | None = None,
    client: OnePasswordClient | None = None,
) -> ConfigType:
    """Resolve `op://...` string fields and return an updated Config."""
    selected = set(fields) if fields is not None else None
    updates: dict[str, str] = {}
    for option in config_options(type(config)):
        if not _option_is_selected(option, selected):
            continue
        value = getattr(config, option.field_name)
        if not isinstance(value, str) or not value.strip().startswith("op://"):
            continue
        try:
            updates[option.field_name] = resolve_op_secret_ref(value, client=client)
        except OnePasswordError as exception:
            raise ConfigError(f"Failed to resolve {option.env_var}: {exception}") from exception
    if not updates:
        return config
    return config.model_copy(update=updates)


def config_snapshot(config: Config) -> dict[str, object]:
    """Return a Config snapshot with secret values reduced to safe states."""
    snapshot: dict[str, object] = {}
    for option in sorted(config_options(type(config)), key=lambda option: option.env_var):
        value = getattr(config, option.field_name)
        snapshot[option.env_var] = _secret_state(value) if option.secret else _snapshot_value(value)
    return snapshot


def _config_option_from_field(field_name: str, field_info: FieldInfo) -> ConfigOption | None:
    extra = field_info.json_schema_extra
    if not isinstance(extra, Mapping):
        return None
    option_payload = cast(Mapping[str, object], extra).get(_CONFIG_OPTION_KEY)
    if not isinstance(option_payload, Mapping):
        return None
    option = _config_option_from_payload(cast(Mapping[str, object], option_payload))
    if option is None:
        return None
    return replace(
        option,
        field_name=field_name,
        cli_flag=option.cli_flag or f"--{field_name.replace('_', '-')}",
    )


def _config_option_payload(option: ConfigOption) -> dict[str, object]:
    return {
        "env_var": option.env_var,
        "cli_flag": option.cli_flag,
        "cli_aliases": list(option.cli_aliases),
        "cli_action": option.cli_action,
        "cli_nargs": option.cli_nargs,
        "cli_const": option.cli_const,
        "metavar": option.metavar,
        "help": option.help,
        "secret": option.secret,
        "required": option.required,
    }


def _config_option_from_payload(payload: Mapping[str, object]) -> ConfigOption | None:
    env_var = payload.get("env_var")
    if not isinstance(env_var, str) or not env_var:
        return None
    cli_flag = payload.get("cli_flag")
    cli_aliases = payload.get("cli_aliases")
    cli_action = payload.get("cli_action")
    cli_nargs = payload.get("cli_nargs")
    metavar = payload.get("metavar")
    help_text = payload.get("help")
    return ConfigOption(
        field_name="",
        env_var=env_var,
        cli_flag=cli_flag if isinstance(cli_flag, str) else "",
        cli_aliases=_string_tuple(cli_aliases),
        cli_action=_cli_action(cli_action),
        cli_nargs=cli_nargs if isinstance(cli_nargs, str | int) else None,
        cli_const=payload.get("cli_const"),
        metavar=metavar if isinstance(metavar, str) else None,
        help=help_text if isinstance(help_text, str) else "",
        secret=payload.get("secret") is True,
        required=payload.get("required") is True,
    )


def _string_tuple(value: object) -> tuple[str, ...]:
    if not isinstance(value, Sequence) or isinstance(value, str | bytes):
        return ()
    return tuple(item for item in cast(Sequence[object], value) if isinstance(item, str))


def _cli_action(value: object) -> Literal["auto", "store_true", "store_false"]:
    if value in {"store_true", "store_false"}:
        return cast(Literal["store_true", "store_false"], value)
    return "auto"


def _selected_raw_value(
    option: ConfigOption,
    env_file_values: Mapping[str, str],
    shell_values: Mapping[str, str],
    override_values: Mapping[str, object],
) -> object:
    raw: object = _MISSING
    if option.env_var in env_file_values:
        raw = env_file_values[option.env_var]
    if option.env_var in shell_values:
        raw = shell_values[option.env_var]
    if option.env_var in override_values:
        raw = override_values[option.env_var]
    if option.field_name in override_values:
        raw = override_values[option.field_name]
    return raw


def _resolve_source_ref(
    option: ConfigOption, raw: object, *, client: OnePasswordClient | None
) -> object:
    if not isinstance(raw, str) or not raw.strip().startswith("op://"):
        return raw
    try:
        return resolve_op_secret_ref(raw, client=client)
    except OnePasswordError as exception:
        raise ConfigError(f"Failed to resolve {option.env_var}: {exception}") from exception


def _prepare_source_value(raw: object, annotation: object, base_dir: Path) -> object:
    if not isinstance(raw, str):
        return raw
    if _is_collection_annotation(annotation):
        return tuple(part.strip() for part in raw.split(",") if part.strip())
    if _is_path_annotation(annotation):
        return _path_for_source(Path(raw), base_dir)
    return raw


def _path_for_source(path: Path | str, base_dir: Path) -> Path:
    expanded = Path(path).expanduser()
    return expanded if expanded.is_absolute() else base_dir / expanded


def _without_none(annotation: object) -> object:
    origin = get_origin(annotation)
    if origin not in (Union, UnionType):
        return annotation
    args = tuple(arg for arg in get_args(annotation) if arg is not type(None))
    return args[0] if len(args) == 1 else annotation


def _is_bool_annotation(annotation: object) -> bool:
    return _without_none(annotation) is bool


def _is_collection_annotation(annotation: object) -> bool:
    target = _without_none(annotation)
    return get_origin(target) in (list, tuple, set, frozenset)


def _is_path_annotation(annotation: object) -> bool:
    target = _without_none(annotation)
    try:
        return isinstance(target, type) and issubclass(target, Path)
    except TypeError:
        return False


def _option_by_name(options: Iterable[ConfigOption], name: str) -> ConfigOption:
    for option in options:
        if name in {option.field_name, option.env_var}:
            return option
    raise ConfigError(f"Unknown Config field or environment variable: {name}")


def _option_is_selected(option: ConfigOption, selected: set[str] | None) -> bool:
    return selected is None or option.field_name in selected or option.env_var in selected


def _value_is_missing(value: object) -> bool:
    if value is None:
        return True
    if isinstance(value, str):
        return not value.strip()
    if isinstance(value, list | tuple | set | frozenset | dict):
        return not value
    return False


def _secret_state(value: object) -> str:
    if _value_is_missing(value):
        return "missing"
    if isinstance(value, str) and value.strip().startswith("op://"):
        return "reference"
    return "provided"


def _snapshot_value(value: object) -> object:
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, list | tuple | set | frozenset):
        items = cast(Iterable[object], value)
        return [str(item) for item in items]
    if isinstance(value, str | int | float | bool) or value is None:
        return value
    return str(value)

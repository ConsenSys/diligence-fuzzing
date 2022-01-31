from pathlib import Path
from typing import List, Optional

import click
import inquirer
import yaml
from click import BadParameter, UsageError, style

from .ide import IDE, IDERepository
from .ide import determine_ide as __determine_ide

CPU_MIN = 1
CPU_MAX = 4


def determine_ide() -> IDE:
    ide = __determine_ide()
    if ide == IDE.SOLIDITY:
        raise UsageError(
            f"Projects using plain solidity files is not supported right now"
        )
    if not click.confirm(
        f"You seem to be using {ide.value.capitalize()}, is that correct?"
    ):
        answers = inquirer.prompt(
            [
                inquirer.List(
                    "ide",
                    message="Please select IDE",
                    choices=[
                        _ide.value.capitalize() for _ide in IDE if _ide != IDE.SOLIDITY
                    ],
                )
            ]
        )
        ide = IDE[answers["ide"].upper()]
    return ide


def determine_targets() -> List[str]:
    message = "Specify folder(s) or smart contract(s) (comma-separated) to fuzz"
    _target_ = Path.cwd().absolute().joinpath("contracts")

    if _target_.exists() and _target_.is_dir():
        if click.confirm(
            f"Do you want to fuzz all smart contracts under {style(_target_, fg='yellow')}?"
        ):
            target = str(_target_)
        else:
            target = click.prompt(message)
    else:
        message = (
            f"We couldn't find any contracts at {style(_target_, fg='yellow')}. "
            + message
        )
        target = click.prompt(message)

    target = [
        t.strip()
        if Path(t.strip()).is_absolute()
        else str(Path.cwd().absolute().joinpath(t.strip()))
        for t in target.split(",")
    ]
    return target


def determine_build_dir(ide: IDE) -> str:
    repo = IDERepository.get_instance()
    artifacts_factory = repo.get_artifacts(ide)

    _build_dir_ = Path(artifacts_factory.get_default_build_dir())
    if not _build_dir_.is_absolute():
        _build_dir_ = Path.cwd().absolute().joinpath(_build_dir_)

    message = "Specify build directory path"

    if _build_dir_.exists() and _build_dir_.is_dir():
        if click.confirm(
            f"Is {style(_build_dir_, fg='yellow')} correct build directory for the project?"
        ):
            build_dir = str(_build_dir_)
        else:
            build_dir = str(click.prompt(message)).strip()
    else:
        message = (
            f"We couldn't find build directory at {style(_build_dir_, fg='yellow')}. "
            + message
        )
        build_dir = str(click.prompt(message)).strip()

    if not Path(build_dir).is_absolute():
        build_dir = str(Path.cwd().absolute().joinpath(build_dir))

    return build_dir


def determine_rpc_url() -> str:
    rpc_url = click.prompt(
        "Specify RPC URL to get seed state from (e.g. local Ganache instance)",
        default="http://localhost:7545",
    )
    return rpc_url


def determine_cpu_cores() -> int:
    def value_proc(value, *args, **kwargs) -> int:
        try:
            val = int(value)
            if CPU_MIN <= val <= CPU_MAX:
                return val
            raise BadParameter("CPU cores should be >= 1 and <= 4")
        except ValueError:
            raise BadParameter("{} is not a valid integer".format(value))

    cpu_cores = click.prompt(
        "Specify CPU cores (1-4) to be used for fuzzing",
        default=1,
        value_proc=value_proc,
    )
    return cpu_cores


def determine_campaign_name() -> str:
    name = Path.cwd().name.lower().replace("-", "_")
    name = click.prompt(
        "Now set fuzzing campaign name prefix", default=name, show_default=True
    )
    return name


def determine_api_key() -> Optional[str]:
    api_key = click.prompt(
        "Provide API key (Could be provided later as an argument to `fuzz run`)",
        default="",
    )
    if api_key == "":
        return None
    return api_key


def recreate_config():
    ide = determine_ide()
    targets = determine_targets()
    build_dir = determine_build_dir(ide)
    rpc_url = determine_rpc_url()
    number_of_cores = determine_cpu_cores()
    campaign_name_prefix = determine_campaign_name()
    api_key = determine_api_key()

    config_path = Path().cwd().joinpath(".fuzz.yml")

    click.echo(
        f"⚡️ Alright! Generating config at {style(config_path, fg='yellow', italic=True)}"
    )

    with config_path.open("w") as f:
        yaml.dump(
            {
                "ci": True,
                "confirm": True,
                "fuzz": {
                    "build_directory": build_dir,
                    "targets": targets,
                    "rpc_url": rpc_url,
                    "number_of_cores": number_of_cores,
                    "campaign_name_prefix": campaign_name_prefix,
                    "api_key": api_key,
                    "faas_url": "https://fuzzing.diligence.tools",
                },
            },
            f,
            default_flow_style=False,
        )

    click.echo("Done 🎉")


def sync_config():
    config_path = Path().cwd().joinpath(".fuzz.yml")
    if not config_path.exists() or not config_path.is_file():
        raise UsageError(f"Could not find config file to re-sync. Create one first.")

    targets = determine_targets()

    click.echo(
        f"⚡️ Alright! Syncing config at {style(config_path, fg='yellow', italic=True)}"
    )
    with config_path.open("r") as f:
        config = yaml.load(f)
        config["fuzz"]["targets"] = targets

    with config_path.open("w") as f:
        yaml.dump(config, f, default_flow_style=False)

    click.echo("Done 🎉")


@click.command("generate-config")
@click.option("--sync", help="Option to update targets", is_flag=True, default=False)
@click.pass_obj
def fuzz_generate_config(ctx, sync: bool) -> None:
    if sync:
        return sync_config()
    recreate_config()
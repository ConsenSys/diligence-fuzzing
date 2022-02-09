import json
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from fuzzing_cli.cli import cli
from fuzzing_cli.fuzz.faas import FaasClient
from fuzzing_cli.fuzz.rpc import RPCClient

from .common import get_test_case, write_config

FAAS_URL = "http://localhost:9899"
ORIGINAL_SOL_CODE = "original sol code here"


def test_fuzz_run(tmp_path, dapptools_project):
    write_config(
        base_path=str(tmp_path),
        build_directory="out",
        not_include=["targets"],
        import_remaps=True,
    )

    with patch.object(
        RPCClient, "contract_exists"
    ) as contract_exists_mock, patch.object(
        RPCClient, "get_all_blocks"
    ) as get_all_blocks_mock, patch.object(
        FaasClient, "start_faas_campaign"
    ) as start_faas_campaign_mock:
        get_all_blocks_mock.return_value = get_test_case(
            "testdata/ganache-all-blocks.json"
        )
        contract_exists_mock.return_value = True
        campaign_id = "560ba03a-8744-4da6-aeaa-a62568ccbf44"
        start_faas_campaign_mock.return_value = campaign_id

        runner = CliRunner()
        result = runner.invoke(
            cli, ["run", f"{tmp_path}/src/Greeter.sol", "-d", "dapptools"]
        )

    contract_exists_mock.assert_called_with(
        "0x7277646075fa72737e1F6114654C5d9949a67dF2"
    )
    contract_exists_mock.assert_called_once()
    get_all_blocks_mock.assert_called_once()
    start_faas_campaign_mock.assert_called_once()
    called_with = start_faas_campaign_mock.call_args
    assert (
        f"You can view campaign here: {FAAS_URL}/campaigns/{campaign_id}"
        in result.output
    )

    request_payload = json.dumps(called_with[0])

    keywords = [
        "parameters",
        "name",
        "corpus",
        "sources",
        "contracts",
        "address-under-test",
        "source",
        "fileIndex",
        "sourcePaths",
        "deployedSourceMap",
        "mainSourceFile",
        "contractName",
        "bytecode",
        "deployedBytecode",
        "sourceMap",
        "deployedSourceMap",
    ]

    for keyword in keywords:
        assert keyword in request_payload

    assert result.exit_code == 0

def test_fuzz_run_no_ide(tmp_path, dapptools_project):
    write_config(
        base_path=str(tmp_path),
        build_directory="out",
        not_include=["targets"],
        import_remaps=True,
    )

    with patch.object(
        RPCClient, "contract_exists"
    ) as contract_exists_mock, patch.object(
        RPCClient, "get_all_blocks"
    ) as get_all_blocks_mock, patch.object(
        FaasClient, "start_faas_campaign"
    ) as start_faas_campaign_mock:
        get_all_blocks_mock.return_value = get_test_case(
            "testdata/ganache-all-blocks.json"
        )
        contract_exists_mock.return_value = True
        campaign_id = "560ba03a-8744-4da6-aeaa-a62568ccbf44"
        start_faas_campaign_mock.return_value = campaign_id

        runner = CliRunner()
        result = runner.invoke(
            cli, ["run", f"{tmp_path}/src/Greeter.sol"]
        )

    contract_exists_mock.assert_called_with(
        "0x7277646075fa72737e1F6114654C5d9949a67dF2"
    )
    contract_exists_mock.assert_called_once()
    get_all_blocks_mock.assert_called_once()

    assert result.exit_code != 0



def test_fuzz_run_map_to_original_source(tmp_path, dapptools_project):
    write_config(
        base_path=str(tmp_path),
        build_directory="out",
        not_include=["targets"],
        import_remaps=True,
    )

    with patch.object(
        RPCClient, "contract_exists"
    ) as contract_exists_mock, patch.object(
        RPCClient, "get_all_blocks"
    ) as get_all_blocks_mock, patch.object(
        FaasClient, "start_faas_campaign"
    ) as start_faas_campaign_mock:
        get_all_blocks_mock.return_value = get_test_case(
            "testdata/ganache-all-blocks.json"
        )
        contract_exists_mock.return_value = True
        campaign_id = "560ba03a-8744-4da6-aeaa-a62568ccbf44"
        start_faas_campaign_mock.return_value = campaign_id

        runner = CliRunner()
        result = runner.invoke(
            cli, ["run", "--map-to-original-source", "-d", "dapptools", f"{tmp_path}/src/Greeter.sol"]
        )

    contract_exists_mock.assert_called_with(
        "0x7277646075fa72737e1F6114654C5d9949a67dF2"
    )
    contract_exists_mock.assert_called_once()
    get_all_blocks_mock.assert_called_once()
    start_faas_campaign_mock.assert_called_once()
    called_with = start_faas_campaign_mock.call_args
    assert (
        f"You can view campaign here: {FAAS_URL}/campaigns/{campaign_id}"
        in result.output
    )

    request_payload = json.dumps(called_with[0])

    assert ORIGINAL_SOL_CODE in request_payload

    keywords = [
        "parameters",
        "name",
        "corpus",
        "sources",
        "contracts",
        "address-under-test",
        "source",
        "fileIndex",
        "sourcePaths",
        "deployedSourceMap",
        "mainSourceFile",
        "contractName",
        "bytecode",
        "deployedBytecode",
        "sourceMap",
        "deployedSourceMap",
    ]

    for keyword in keywords:
        assert keyword in request_payload

    assert result.exit_code == 0


@pytest.mark.parametrize("keyword", ("run", "disarm", "arm", "run"))
def test_fuzz_subcommands_present(keyword):
    runner = CliRunner()

    result = runner.invoke(cli, ["--help"])

    assert keyword in result.output


@patch("fuzzing_cli.fuzz.scribble.ScribbleMixin.instrument_solc_in_place")
def test_fuzz_arm(mock, tmp_path, dapptools_project):
    write_config(
        base_path=str(tmp_path),
        build_directory="out",
        not_include=["targets"],
        import_remaps=True,
    )
    runner = CliRunner()
    result = runner.invoke(cli, ["arm", f"{tmp_path}/src/Greeter.sol"])

    mock.assert_called()
    mock.assert_called_with(
        file_list=(f"{tmp_path}/src/Greeter.sol",),
        scribble_path="scribble",
        remappings=['@openzeppelin=lib/openzeppelin-contracts'],
        solc_version=None,
    )
    assert result.exit_code == 0


@patch("fuzzing_cli.fuzz.scribble.ScribbleMixin.disarm_solc_in_place")
def test_fuzz_disarm(mock, tmp_path, dapptools_project):
    write_config(
        base_path=str(tmp_path),
        build_directory="out",
        not_include=["targets"],
        import_remaps=True,
    )
    runner = CliRunner()
    result = runner.invoke(cli, ["disarm", f"{tmp_path}/src/Greeter.sol"])

    mock.assert_called()
    mock.assert_called_with(
        file_list=(f"{tmp_path}/src/Greeter.sol",),
        scribble_path="scribble",
        remappings=['@openzeppelin=lib/openzeppelin-contracts'],
        solc_version=None,
    )
    assert result.exit_code == 0

import json
import os
from os import remove
from pathlib import Path

import pytest

from tests.common import get_test_case


@pytest.fixture()
def truffle_project(tmp_path, request):
    artifact = get_test_case("testdata/truffle-artifact.json")
    # switch to temp dir if requested
    if hasattr(request, "param") and request.param:
        os.chdir(str(tmp_path))

    # add truffle project structure
    os.makedirs(str(tmp_path / "build/contracts/MasterChefV2.sol/"))
    os.makedirs(str(tmp_path / "contracts"))

    # we create the config file NOT in the temp directory, but in the CWD because it's where pytest
    # is running and looking for the file. At the end of the test we delete the file
    with open("./truffle-config.js", "w+") as config_f:
        json.dump("sample", config_f)

    artifact["contractName"] = f"Foo"
    artifact["sourcePath"] = f"{tmp_path}/contracts/sample.sol"

    # add sample brownie artifact
    with open(tmp_path / "build/contracts/Foo.json", "w+") as artifact_f:
        json.dump(artifact, artifact_f)
    with open(tmp_path / "contracts/sample.sol", "w+") as sol_f:
        sol_f.write("sol code here")

    yield {"switch_dir": hasattr(request, "param") and request.param}
    os.remove(Path("./truffle-config.js").absolute())


@pytest.fixture()
def brownie_project(tmp_path):
    artifact = get_test_case("testdata/brownie-artifact.json")

    # add brownie project structure
    os.makedirs(str(tmp_path / "build/contracts/"))
    os.makedirs(str(tmp_path / "contracts/"))

    # we create the config file NOT in the temp directory, but in the CWD because it's where pytest
    # is running and looking for the file. At the end of the test we delete the file
    with open("brownie-config.yaml", "w+") as config_f:
        json.dump("sample", config_f)

    # patch brownie artifact with temp path
    artifact["allSourcePaths"][0] = f"{tmp_path}/contracts/sample.sol"
    artifact["sourcePath"] = f"{tmp_path}/contracts/sample.sol"

    # add sample brownie artifact
    with open(tmp_path / "build/contracts/Foo.json", "w+") as artifact_f:
        json.dump(artifact, artifact_f)
    with open(tmp_path / "contracts/sample.sol", "w+") as sol_f:
        sol_f.write("sol code here")
    with open(tmp_path / "contracts/sample.sol.original", "w+") as sol_f:
        sol_f.write("original sol code here")

    yield None
    os.remove(Path("brownie-config.yaml").absolute())


@pytest.fixture()
def dapptools_project(tmp_path):
    original_artifact = get_test_case("testdata/dapptools_artifact.json")

    # add dapptools project structure
    os.makedirs(str(tmp_path / "out/"))
    os.makedirs(str(tmp_path / "src/test/utils/"))
    os.makedirs(str(tmp_path / "lib/openzeppelin-contracts/contracts/utils/"))
    os.makedirs(str(tmp_path / "lib/openzeppelin-contracts/contracts/access/"))
    os.makedirs(str(tmp_path / "lib/ds-test/src/"))

    # create dapptools config file
    # we create the config file NOT in the temp directory, but in the CWD because it's where pytest
    # is running and looking for the file. At the end of the test we delete the file
    with open(".dapprc", "w+") as config_f:
        json.dump("sample", config_f)

    # patch dapptools artifact with temp path
    artifact = {"sources": {}, "contracts": {}}
    for k, v in original_artifact["sources"].items():
        artifact["sources"][f"{tmp_path}/{k}"] = v
    for k, v in original_artifact["contracts"].items():
        artifact["contracts"][f"{tmp_path}/{k}"] = v

    # Create a temp dapptools artifacts file with the patched locations
    with open(tmp_path / "out/dapp.sol.json", "w+") as artifact_f:
        json.dump(artifact, artifact_f)
    # Create the temp solidity files
    for k, v in artifact["contracts"].items():
        with open(k, "w+") as sol_f:
            sol_f.write("sol code here")
        with open(k+".original", "w+") as original_sol_f:
            original_sol_f.write("original sol code here")

    yield None
    os.remove(Path(".dapprc").absolute())


@pytest.fixture()
def hardhat_project(tmp_path, request):
    artifact = get_test_case("testdata/hardhat-artifact.json")
    different_contracts_artifact = get_test_case(
        "testdata/hardhat-artifact-different-contract-name.json"
    )
    build_artifact = get_test_case("testdata/hardhat-build-info-artifact.json")
    build_artifact_1 = get_test_case("testdata/hardhat-build-info-artifact-1.json")

    # switch to temp dir if requested
    if hasattr(request, "param") and request.param:
        os.chdir(str(tmp_path))

    # add hardhat project structure
    os.makedirs(str(tmp_path / "artifacts/contracts/MasterChefV2.sol/"))
    os.makedirs(str(tmp_path / "artifacts/contracts/sample.sol/"))
    os.makedirs(str(tmp_path / "artifacts/build-info/"))
    os.makedirs(str(tmp_path / "contracts"))

    # add sample brownie artifact
    with open(
        tmp_path / "artifacts/build-info/b78e6e91d6666dbbf407d4a383cd8177.json", "w+"
    ) as artifact_f:
        json.dump(build_artifact, artifact_f)

    with open(
        tmp_path / "artifacts/build-info/1971e920b375c86605b83cbedee1f092.json", "w+"
    ) as artifact_f:
        json.dump(build_artifact_1, artifact_f)

    with open("./hardhat.config.ts", "w+") as config_f:
        json.dump("sample", config_f)

    for filename, content in artifact.items():
        with open(
            tmp_path / f"artifacts/contracts/MasterChefV2.sol/{filename}.json", "w+"
        ) as sol_f:
            json.dump(content, sol_f)

    for filename, content in different_contracts_artifact.items():
        with open(
            tmp_path / f"artifacts/contracts/sample.sol/{filename}.json", "w+"
        ) as sol_f:
            json.dump(content, sol_f)

    with open(tmp_path / "contracts/MasterChefV2.sol", "w+") as sol_f:
        sol_f.write("sol code here")

    with open(tmp_path / "contracts/sample.sol", "w+") as sol_f:
        sol_f.write("sol code here")

    with open(tmp_path / "contracts/MasterChefV2.sol.original", "w+") as sol_f:
        sol_f.write("original sol code here")

    with open(tmp_path / "contracts/sample.sol.original", "w+") as sol_f:
        sol_f.write("original sol code here")

    yield {"switch_dir": hasattr(request, "param") and request.param}

    os.remove(Path("./hardhat.config.ts").absolute())


@pytest.fixture()
def isolated_hardhat_project(tmp_path):
    artifact = get_test_case("testdata/hardhat-artifact.json")
    different_contracts_artifact = get_test_case(
        "testdata/hardhat-artifact-different-contract-name.json"
    )
    build_artifact = get_test_case("testdata/hardhat-build-info-artifact.json")
    build_artifact_1 = get_test_case("testdata/hardhat-build-info-artifact-1.json")

    # add hardhat project structure
    os.makedirs(str(tmp_path / "artifacts/contracts/MasterChefV2.sol/"))
    os.makedirs(str(tmp_path / "artifacts/contracts/sample.sol/"))
    os.makedirs(str(tmp_path / "artifacts/build-info/"))
    os.makedirs(str(tmp_path / "contracts"))

    # add sample brownie artifact
    with open(
        tmp_path / "artifacts/build-info/b78e6e91d6666dbbf407d4a383cd8177.json", "w+"
    ) as artifact_f:
        json.dump(build_artifact, artifact_f)

    with open(
        tmp_path / "artifacts/build-info/1971e920b375c86605b83cbedee1f092.json", "w+"
    ) as artifact_f:
        json.dump(build_artifact_1, artifact_f)

    with open(f"{tmp_path}/hardhat.config.ts", "w+") as config_f:
        json.dump("sample", config_f)

    for filename, content in artifact.items():
        with open(
            tmp_path / f"artifacts/contracts/MasterChefV2.sol/{filename}.json", "w+"
        ) as sol_f:
            json.dump(content, sol_f)

    for filename, content in different_contracts_artifact.items():
        with open(
            tmp_path / f"artifacts/contracts/sample.sol/{filename}.json", "w+"
        ) as sol_f:
            json.dump(content, sol_f)

    with open(tmp_path / "contracts/MasterChefV2.sol", "w+") as sol_f:
        sol_f.write("sol code here")

    with open(tmp_path / "contracts/sample.sol", "w+") as sol_f:
        sol_f.write("sol code here")

    with open(tmp_path / "contracts/MasterChefV2.sol.original", "w+") as sol_f:
        sol_f.write("original sol code here")

    with open(tmp_path / "contracts/sample.sol.original", "w+") as sol_f:
        sol_f.write("original sol code here")


@pytest.fixture()
def isolated_brownie_project(tmp_path):
    artifact = get_test_case("testdata/brownie-artifact.json")

    # add brownie project structure
    os.makedirs(str(tmp_path / "build/contracts/"))
    os.makedirs(str(tmp_path / "contracts/"))

    with open(f"{tmp_path}/brownie-config.yaml", "w+") as config_f:
        json.dump("sample", config_f)

    # patch brownie artifact with temp path
    artifact["allSourcePaths"][0] = f"{tmp_path}/contracts/sample.sol"
    artifact["sourcePath"] = f"{tmp_path}/contracts/sample.sol"

    # add sample brownie artifact
    with open(tmp_path / "build/contracts/Foo.json", "w+") as artifact_f:
        json.dump(artifact, artifact_f)
    with open(tmp_path / "contracts/sample.sol", "w+") as sol_f:
        sol_f.write("sol code here")
    with open(tmp_path / "contracts/sample.sol.original", "w+") as sol_f:
        sol_f.write("original sol code here")


@pytest.fixture()
def isolated_truffle_project(tmp_path):
    artifact = get_test_case("testdata/truffle-artifact.json")

    # add truffle project structure
    os.makedirs(str(tmp_path / "build/contracts/MasterChefV2.sol/"))
    os.makedirs(str(tmp_path / "contracts"))

    with open(f"{tmp_path}/truffle-config.js", "w+") as config_f:
        json.dump("sample", config_f)

    artifact["contractName"] = "Foo"
    artifact["sourcePath"] = f"{tmp_path}/contracts/sample.sol"

    # add sample brownie artifact
    with open(tmp_path / "build/contracts/Foo.json", "w+") as artifact_f:
        json.dump(artifact, artifact_f)
    with open(tmp_path / "contracts/sample.sol", "w+") as sol_f:
        sol_f.write("sol code here")


@pytest.fixture(autouse=True)
def teardown():
    yield
    try:
        remove(".fuzz.yml")
    except:
        pass

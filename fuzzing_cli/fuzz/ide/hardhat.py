import json
import os
from functools import lru_cache
from os.path import abspath, commonpath, relpath
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from fuzzing_cli.fuzz.ide.generic import Contract, IDEArtifacts, Source

from ...util import files_by_directory, get_content_from_file


class HardhatArtifacts(IDEArtifacts):
    def __init__(
        self,
        targets: Optional[List[str]] = None,
        build_dir: Optional[Path] = None,
        map_to_original_source: bool = False,
    ):
        super(HardhatArtifacts, self).__init__(
            targets,
            Path(build_dir).absolute() or Path("./artifacts").absolute(),
            map_to_original_source,
        )
        self._include = [abspath(fp) for fp in self._include]

    @classmethod
    def get_name(cls) -> str:
        return "hardhat"

    @classmethod
    def validate_project(cls) -> bool:
        root_dir = Path.cwd().absolute()
        files = list(os.walk(root_dir))[0][2]
        return "hardhat.config.ts" in files or "hardhat.config.js" in files

    @property
    def contracts(self) -> List[Contract]:
        return self.fetch_data()[0]

    @property
    def sources(self) -> Dict[str, Source]:
        return self.fetch_data()[1]

    @lru_cache(maxsize=1)
    def fetch_data(self) -> Tuple[List[Contract], Dict[str, Source]]:
        result_contracts = {}
        result_sources = {}

        for file_path in self._include:
            cp = commonpath([self.build_dir, file_path])
            relative_file_path = relpath(file_path, cp)

            if relative_file_path in result_contracts:
                continue

            contract_artifacts = {}
            build_infos = {}
            contract_build_info = {}

            for fp in files_by_directory(
                str(self.build_dir.joinpath(relative_file_path)), "json"
            ):
                path = Path(fp)
                with path.open("r") as file:
                    file_artifact = json.load(file)
                    if path.name.endswith("dbg.json"):
                        build_info_name = Path(file_artifact["buildInfo"]).name
                        with self.build_dir.joinpath(
                            f"build-info/{build_info_name}"
                        ).open("r") as bfile:
                            build_infos[build_info_name] = json.load(bfile)
                        contract_build_info[
                            path.name.replace(".dbg.json", "")
                        ] = build_info_name
                    else:
                        contract_artifacts[path.stem] = file_artifact

            result_contracts[relative_file_path] = []

            for contract_name, contract_artifact in contract_artifacts.items():
                build_info = build_infos[contract_build_info[contract_name]]
                contract = build_info["output"]["contracts"][relative_file_path][
                    contract_name
                ]
                if contract["evm"]["bytecode"]["object"] == "":
                    continue

                ignored_sources = set()
                for generatedSource in contract["evm"]["deployedBytecode"].get(
                    "generatedSources", []
                ):
                    if generatedSource["language"].lower() == "yul" and type(
                        generatedSource["id"] is int
                    ):
                        ignored_sources.add(generatedSource["id"])

                result_contracts[relative_file_path] += [
                    {
                        "sourcePaths": {
                            i: k
                            for i, k in enumerate(
                                build_info["output"]["contracts"].keys()
                            )
                        },
                        "deployedSourceMap": contract["evm"]["deployedBytecode"][
                            "sourceMap"
                        ],
                        "deployedBytecode": contract["evm"]["deployedBytecode"][
                            "object"
                        ],
                        "sourceMap": contract["evm"]["bytecode"]["sourceMap"],
                        "bytecode": contract["evm"]["bytecode"]["object"],
                        "contractName": contract_artifact["contractName"],
                        "mainSourceFile": contract_artifact["sourceName"],
                        "ignoredSources": list(ignored_sources),
                    }
                ]

                for source_file_dep, data in build_info["output"]["sources"].items():
                    if source_file_dep in result_sources.keys():
                        continue

                    result_sources[source_file_dep] = {
                        "fileIndex": data["id"],
                        "source": build_info["input"]["sources"][source_file_dep][
                            "content"
                        ],
                        "ast": data["ast"],
                    }

                    if (
                        self.map_to_original_source
                        and Path(source_file_dep + ".original").is_file()
                    ):
                        # we check if the current source file has a non instrumented version
                        # if it does, we include that one as the source code
                        result_sources[source_file_dep][
                            "source"
                        ] = get_content_from_file(source_file_dep + ".original")

        return self.flatten_contracts(result_contracts), result_sources

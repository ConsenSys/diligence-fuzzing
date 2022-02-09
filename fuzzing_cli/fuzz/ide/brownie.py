import logging
import os
from functools import lru_cache
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from fuzzing_cli.fuzz.exceptions import BuildArtifactsError
from fuzzing_cli.fuzz.ide.generic import Contract, IDEArtifacts, Source

from ...util import get_content_from_file

LOGGER = logging.getLogger("fuzzing-cli")


class BrownieArtifacts(IDEArtifacts):
    def __init__(
        self,
        targets: Optional[List[str]] = None,
        build_dir: Optional[Path] = None,
        map_to_original_source: bool = False,
    ):
        super(BrownieArtifacts, self).__init__(
            targets, build_dir or Path("./build/contracts"), map_to_original_source
        )

    @classmethod
    def get_name(cls) -> str:
        return "brownie"

    @classmethod
    def validate_project(cls) -> bool:
        root_dir = Path.cwd().absolute()
        files = list(os.walk(root_dir))[0][2]
        return "brownie-config.yaml" in files

    @property
    def contracts(self) -> List[Contract]:
        return self.fetch_data()[0]

    @property
    def sources(self) -> Dict[str, Source]:
        return self.fetch_data()[1]

    @staticmethod
    def get_compiler_generated_source_ids(
        source_map: str, sources: Dict[str, str]
    ) -> List[int]:
        # this method is necessary because brownie does not preserve `generatedSources` for deployedBytecode
        # from solidity compiler's output (i.e. `deployedGeneratedSources`)
        sm = source_map.split(";")
        allFileIds = set()
        for c in sm:
            component = c.split(":")
            if len(component) < 3 or component[2] == "":
                continue
            allFileIds.add(component[2])
        return [int(fileId) for fileId in allFileIds if fileId not in sources.keys()]

    @lru_cache(maxsize=1)
    def fetch_data(self) -> Tuple[List[Contract], Dict[str, Source]]:
        """ example build_files_by_source_file
            {
                'contracts/Token.sol':
                    {
                        'abi':... ,
                        'ast':... ,
                        'source':...,
                        ''
                    }
            }
        """
        build_files_by_source_file = self._get_build_artifacts(self.build_dir)
        result_contracts = {}
        result_sources = {}

        # ( 'contracts/Token.sol', {'allSourcePaths':..., 'deployedSourceMap': ... } )
        for source_file, contracts in build_files_by_source_file.items():
            if source_file not in self._include:
                continue
            result_contracts[source_file] = []
            for contract in contracts:
                # We get the build items from brownie and rename them into the properties used by the FaaS
                try:
                    result_contracts[source_file] += [
                        {
                            "sourcePaths": contract["allSourcePaths"],
                            "deployedSourceMap": contract["deployedSourceMap"],
                            "deployedBytecode": contract["deployedBytecode"],
                            "sourceMap": contract["sourceMap"],
                            "bytecode": contract["bytecode"],
                            "contractName": contract["contractName"],
                            "mainSourceFile": contract["sourcePath"],
                            "ignoredSources": self.get_compiler_generated_source_ids(
                                source_map=contract["deployedSourceMap"],
                                sources=contract["allSourcePaths"],
                            ),
                        }
                    ]
                except KeyError as e:
                    raise BuildArtifactsError(
                        f"Build artifact did not contain expected key. Contract: {contract}: \n{e}"
                    )

                for file_index, source_file_dep in contract["allSourcePaths"].items():
                    if source_file_dep in result_sources.keys():
                        continue

                    if source_file_dep not in build_files_by_source_file:
                        LOGGER.debug(f"{source_file} not found.")
                        continue

                    # We can select any dict on the build_files_by_source_file[source_file] array
                    # because the .source and .ast values will be the same in all.
                    target_file = build_files_by_source_file[source_file_dep][0]
                    result_sources[source_file_dep] = {
                        "fileIndex": file_index,
                        "source": target_file["source"],
                        "ast": target_file["ast"],
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

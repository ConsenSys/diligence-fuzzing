import base64
from typing import List, Optional, Tuple

import click


class FuzzingOptions:
    def __init__(
        self,
        ide: Optional[str] = None,
        build_directory: str = None,
        deployed_contract_address: Optional[str] = None,
        target: Optional[List[str]] = None,
        map_to_original_source: bool = False,
        rpc_url: str = "http://localhost:7545",
        faas_url: str = "https://fuzzing.diligence.tools",
        number_of_cores: int = 2,
        campaign_name_prefix: str = "untitled",
        corpus_target: Optional[str] = None,
        additional_contracts_addresses: Optional[List[str]] = None,
        dry_run: bool = False,
        refresh_token: Optional[str] = None,
        api_key: Optional[str] = None,
        project: Optional[str] = None,
    ):
        self.ide: Optional[str] = ide and ide.lower()
        self.additional_contracts_addresses = additional_contracts_addresses
        self.corpus_target = corpus_target
        self.map_to_original_source = map_to_original_source
        self.dry_run = dry_run
        self.api_key = api_key
        self.build_directory = build_directory
        self.deployed_contract_address = deployed_contract_address
        self.target = target
        self.rpc_url = rpc_url
        self.faas_url = faas_url
        self.number_of_cores = int(number_of_cores)
        self.campaign_name_prefix = campaign_name_prefix

        self.auth_endpoint = None
        self.refresh_token = None
        self.auth_client_id = None

        self.validate(refresh_token)

        self.project = project

        if not api_key:
            self.auth_endpoint, self.auth_client_id, self.refresh_token = self._decode_refresh_token(
                refresh_token
            )

    @staticmethod
    def _decode_refresh_token(refresh_token: str) -> Tuple[str, str, str]:
        error_message = (
            "Refresh Token is malformed. The format is `<auth_data>::<refresh_token>`"
        )
        # format is "<auth_data>::<refresh_token>"
        if refresh_token.count("::") != 1:
            raise click.exceptions.UsageError(error_message)
        data, rt = refresh_token.split("::")
        if not data or not rt:
            raise click.exceptions.UsageError(error_message)
        try:
            decoded_data = base64.b64decode(data).decode()
        except:
            raise click.exceptions.UsageError(error_message)
        if decoded_data.count("::") != 1:
            raise click.exceptions.UsageError(error_message)
        client_id, endpoint = decoded_data.split("::")
        if not client_id or not endpoint:
            raise click.exceptions.UsageError(error_message)
        return endpoint, client_id, rt

    def validate(self, refresh_token: str):
        if not self.build_directory:
            raise click.exceptions.UsageError(
                "Build directory not provided. You need to set the `build_directory` "
                "on the `fuzz` key of your .fuzz.yml config file."
            )
        if not self.api_key and not refresh_token:
            raise click.exceptions.UsageError(
                "API key or Refresh Token were not provided. You need to provide either an API key or a Refresh Token"
                "as the `--api-key` or `--refresh-token` parameters respectively of the fuzz run command"
                "or set `api_key` or `refresh_token` on the `fuzz` key of your .fuzz.yml config file."
            )
        if not self.deployed_contract_address:
            raise click.exceptions.UsageError(
                "Deployed contract address not provided. You need to provide an address as the `--address` "
                "parameter of the fuzz run command.\nYou can also set the `deployed_contract_address`"
                "on the `fuzz` key of your .fuzz.yml config file."
            )
        if not self.target:
            raise click.exceptions.UsageError(
                "Target not provided. You need to provide a target as the last parameter of the fuzz run command."
                "\nYou can also set the `targets` on the `fuzz` key of your .fuzz.yml config file."
            )

from .brownie import BrownieArtifacts
from .dapptools import DapptoolsArtifacts
from .generic import Contract, IDEArtifacts, IDEPayload, Source
from .hardhat import HardhatArtifacts
from .repository import IDERepository
from .truffle import TruffleArtifacts

# Initializing of IDERepository singleton
# NOTE: Each new IDE should register respective class here
repo = IDERepository()

repo.register_ide(TruffleArtifacts)
repo.register_ide(HardhatArtifacts)
repo.register_ide(BrownieArtifacts)
repo.register_ide(DapptoolsArtifacts)

IDERepository.set_instance(repo)

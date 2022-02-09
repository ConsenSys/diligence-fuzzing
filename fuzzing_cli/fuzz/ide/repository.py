from typing import Dict, Optional, Type

from .generic import IDEArtifacts


class IDENotRegistered(Exception):
    def __init__(self, ide_name: str):
        super(IDENotRegistered, self).__init__(
            f'"{ide_name.capitalize()}" IDE not registered'
        )


class JobNotRegistered(Exception):
    def __init__(self, ide):
        super(JobNotRegistered, self).__init__(f"Job for {ide.name} not registered")


class IDERepository:
    instance: "IDERepository"

    def __init__(self):
        self.ides: Dict[str, Type[IDEArtifacts]] = {}

    @classmethod
    def set_instance(cls, _instance: "IDERepository"):
        cls.instance = _instance

    @classmethod
    def get_instance(cls) -> "IDERepository":
        return cls.instance

    def register_ide(self, _class: Type[IDEArtifacts]):
        self.ides[_class.get_name()] = _class

    def get_ide(self, name: str) -> Type[IDEArtifacts]:
        ide_class = self.ides.get(name)
        if not ide_class:
            raise IDENotRegistered(name)
        return ide_class

    def detect_ide(self) -> Optional[Type[IDEArtifacts]]:
        for ide in self.ides.values():
            if ide.validate_project():
                return ide
        return None

"""Resolve Objective-C method spellings through the Hopper bridge's name lookup."""

import json
from pathlib import Path
import sys


class NamedDocument:
    names = {
        "-[QuickOpenCommands buildPredicateQueryFrom:]": 0x100002890,
        "+[Updater sharedInstance]": 0x100004554,
        "-[Both value]": 0x100005000,
        "+[Both value]": 0x100005100,
        "QuickOpenCommands::literal": 0x100006000,
    }

    def getAddressForName(self, name):
        return self.names.get(name, -1)


def load_bridge(path):
    namespace = {"__file__": path, "__name__": "rea_hopper_bridge"}
    source = Path(path).read_text(encoding="utf-8")
    exec(compile(source, path, "exec"), namespace)
    return namespace


def resolve(bridge, value):
    try:
        return {"address": bridge["_hex"](bridge["_address"](NamedDocument(), value))}
    except bridge["InvalidRequestError"] as error:
        return {"error": str(error)}


bridge = load_bridge(sys.argv[1])
print(
    json.dumps(
        {
            value: resolve(bridge, value)
            for value in [
                "-[QuickOpenCommands buildPredicateQueryFrom:]",
                "QuickOpenCommands::buildPredicateQueryFrom:",
                "Updater::sharedInstance",
                "Both::value",
                "QuickOpenCommands::literal",
                "Missing::value",
            ]
        }
    )
)

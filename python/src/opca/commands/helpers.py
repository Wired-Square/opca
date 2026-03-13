# opca/commands/helpers.py

from __future__ import annotations

import argparse
from typing import Type
from pydantic import BaseModel

def prune_opts(model: Type[BaseModel], ns: argparse.Namespace) -> BaseModel:
    """
    Prune an argparse namespace down to fields the Pydantic model knows about,
    then validate. Unknown args (account, vault, handler, etc.) are ignored.
    """
    data = vars(ns)
    allowed = model.model_fields.keys()
    pruned = {k: data[k] for k in allowed if k in data}

    return model.model_validate(pruned)

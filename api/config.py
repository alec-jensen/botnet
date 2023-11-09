# Config class for kidney-bot
# Copyright (C) 2023  Alec Jensen
# Full license at LICENSE.md

import json
import logging
from database import convert_except_none


class Config:
    def __init__(self):
        with open('config.json', 'r') as f:
            self.conf_json: dict = json.load(f)

        try:
            self.dbstring: str = self.conf_json['dbstring']
        except KeyError as e:
            raise KeyError(f'Config file is missing a required option: {e}')

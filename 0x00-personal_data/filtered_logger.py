#!/usr/bin/env python3

"""
This module contains a method that securely obfuscates the personal data
stored in a log file.
"""
import re
from typing import List
import logging
import os


def filter_datum(fields: List[str], redaction: str, message: str,
                 separator: str) -> str:
    """
    Returns the log message obfuscated.
    """
    for field in fields:
        message = re.sub(f'{field}=.*?{separator}',
                         f'{field}={redaction}{separator}', message)
    return message

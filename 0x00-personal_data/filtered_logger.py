#!/usr/bin/env python3
"""Logging Module"""

import re
import logging
from mysql.connector import connection
from os import environ
from typing import List

PII_FIELDS = ("name", "email", "phone", "ssn", "password")


class RedactingFormatter(logging.Formatter):
    """Redacting Formatter class"""

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """Format method to class"""
        return filter_datum(
            self.fields, self.REDACTION, super().format(record), self.SEPARATOR
        )


def filter_datum(
    fields: List[str], redaction: str, message: str, separator: str
) -> str:
    """Formatting"""
    for field in fields:
        message = re.sub(f"{field}=.*?{separator}",
                         f"{field}={redaction}{separator}", message)
    return message


def get_logger() -> logging.Logger:
    """get_logger implementation"""
    logger = logging.getLogger("user_data")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    handler = logging.StreamHandler()
    handler.setFormatter(RedactingFormatter(PII_FIELDS))
    logger.addHandler(handler)
    return logger


def get_db() -> connection.MySQLConnection:
    """Redacting Formatter class."""
    connector = connection.MySQLConnection(
        user=environ.get("PERSONAL_DATA_DB_USERNAME", "root"),
        password=environ.get("PERSONAL_DATA_DB_PASSWORD", ""),
        host=environ.get("PERSONAL_DATA_DB_HOST", "localhost"),
        database=environ.get("PERSONAL_DATA_DB_NAME"))
    return connector


def main():
    """Redacting Formatter class."""
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users;")

    result = cursor.fetchall()
    for data in result:
        message = (
            f"name={data[0]}; "
            + f"email={data[1]}; "
            + f"phone={data[2]}; "
            + f"ssn={data[3]}; "
            + f"password={data[4]}; "
            + f"ip={data[5]}; "
            + f"last_login={data[6]}; "
            + f"user_agent={data[7]};"
        )
        print(message)
        formatter = RedactingFormatter(PII_FIELDS)
        formatter.format(
            logging.LogRecord(
                "my_logger", logging.INFO, None, None, message, None, None
            )
        )
    cursor.close()
    db.close()


if __name__ == "__main__":
    main()

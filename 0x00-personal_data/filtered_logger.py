#!/usr/bin/env python3
"""
Module to interact with a MySQL database and log user data.

This module includes a RedactingFormatter class for logging, a filter_datum
function for redacting sensitive information in log messages, a get_logger
function to obtain a configured logger, and a get_db function to connect to
a MySQL database. The main function retrieves user data from the database,
formats the information, and logs it using the configured logger.

Constants:
    PII_FIELDS (Tuple[str]): Tuple of personally identifiable information (PII)
        fields to be redacted in log messages.

Classes:
    RedactingFormatter: Custom logging formatter to redact
        sensitive information.

Functions:
    filter_datum: Redacts specified PII fields in a log message.
    get_logger: Configures and returns a logger with a RedactingFormatter.
    get_db: Connects to a MySQL database and returns the connection object.

Usage:
    The script can be executed to retrieve and log user data from a MySQL
    database. Ensure that the necessary environment variables for database
    connection are set before running the script.
"""

import re
import logging
import mysql.connector
from os import environ
from typing import List

PII_FIELDS = ("name", "email", "phone", "ssn", "password")


class RedactingFormatter(logging.Formatter):
    """
    Custom logging formatter for redacting PII fields in log messages.

    Attributes:
        REDACTION (str): The string used for redacting sensitive information.
        FORMAT (str): The log message format with placeholders for log record
            attributes.
        SEPARATOR (str): The separator used to distinguish different fields in
            log messages.

    Methods:
        __init__: Initializes the RedactingFormatter with specified PII fields.
        format: Formats the log record and redacts PII fields in the message.
    """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        """
        Initialize the RedactingFormatter.

        Parameters:
            fields (List[str]): List of PII fields to be redacted
                in log messages.
        """
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """
        Format the log record and redact specified PII fields.

        Parameters:
            record (logging.LogRecord): The log record to be formatted.

        Returns:
            str: The formatted log message with redacted PII fields.
        """
        return filter_datum(
            self.fields, self.REDACTION, super().format(record), self.SEPARATOR
        )


def filter_datum(
    fields: List[str], redaction: str, message: str, separator: str
) -> str:
    """
    Redact specified PII fields in a given message string.

    Parameters:
        fields (List[str]): List of PII fields to be redacted.
        redaction (str): The string used for redacting sensitive information.
        message (str): The input message string containing PII fields.
        separator (str): The separator used to distinguish different fields in
            the message.

    Returns:
        str: The message string with redacted PII fields.
    """
    for field in fields:
        message = re.sub(f"{field}=.*?{separator}",
                         f"{field}={redaction}{separator}", message)
    return message


def get_logger() -> logging.Logger:
    """
    Create and configure a logger with the RedactingFormatter.

    Returns:
        logging.Logger: The configured logger object.
    """
    logger = logging.getLogger("user_data")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    handler = logging.StreamHandler()
    handler.setFormatter(RedactingFormatter(PII_FIELDS))
    logger.addHandler(handler)
    return logger


def get_db() -> mysql.connector.connection.MySQLConnection:
    """
    Establish a connection to a MySQL database using environment variables.

    Returns:
        mysql.connector.connection.MySQLConnection: The database connection
            object.
    """
    connector = mysql.connector.connection.MySQLConnection(
        user=environ.get("PERSONAL_DATA_DB_USERNAME", "root"),
        password=environ.get("PERSONAL_DATA_DB_PASSWORD", ""),
        host=environ.get("PERSONAL_DATA_DB_HOST", "localhost"),
        database=environ.get("PERSONAL_DATA_DB_NAME"),
    )
    return connector


def main():
    """
    Demonstrate the usage of logging and redacting formatter.
    """
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

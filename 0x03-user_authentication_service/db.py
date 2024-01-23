#!/usr/bin/env python3
"""Database Module for User Object-Relational Mapping

This module provides a DB class for managing user data using SQLAlchemy.
Including methods for adding, finding,
and updating user information in the database.
"""

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import InvalidRequestError
from sqlalchemy.orm.exc import NoResultFound
from typing import TypeVar
from user import Base, User


class DB:
    """DB class for Object-Relational Mapping.

    This class provides methods for interacting with the database,
    including adding, finding, and updating users.
    """

    def __init__(self):
        """Initialize a new DB instance."""
        self._engine = create_engine("sqlite:///a.db", echo=False)
        Base.metadata.drop_all(self._engine)
        Base.metadata.create_all(self._engine)
        self.__session = None

    @property
    def _session(self):
        """Session Getter Method."""
        if self.__session is None:
            DBSession = sessionmaker(bind=self._engine)
            self.__session = DBSession()
        return self.__session

    def add_user(self, email: str, hashed_password: str) -> User:
        """Adds a new user to the database and returns the user object.

        Parameters:
            email (str): Email address of the user.
            hashed_password (str): Hashed password of the user.

        Returns:
            User: The User object representing the added user.
        """
        user = User(email=email, hashed_password=hashed_password)
        self._session.add(user)
        self._session.commit()
        return user

    def find_user_by(self, **kwargs) -> User:
        """Find a user in the database based on given criteria.

        Parameters:
            **kwargs: Filter criteria for finding the user.

        Returns:
            User: The User object representing the found user.

        Raises:
            InvalidRequestError: If invalid request parameters are provided.
            NoResultFound: If no user is found with the given criteria.
        """
        if not kwargs:
            raise InvalidRequestError

        column_names = User.__table__.columns.keys()
        for key in kwargs.keys():
            if key not in column_names:
                raise InvalidRequestError

        user = self._session.query(User).filter_by(**kwargs).first()
        if user is None:
            raise NoResultFound
        return user

    def update_user(self, user_id: int, **kwargs) -> None:
        """Updates user attributes based on the provided keyword arguments.

        Parameters:
            user_id (int): The ID of the user to be updated.
            **kwargs: Updated attributes for the user.

        Raises:
            ValueError: If invalid attributes are provided for updating.
        """
        user = self.find_user_by(id=user_id)

        column_names = User.__table__.columns.keys()
        for key in kwargs.keys():
            if key not in column_names:
                raise ValueError

        for key, value in kwargs.items():
            setattr(user, key, value)

        self._session.commit()

import datetime
from sqlalchemy import Column, Integer, String, ForeignKey, DateTime, UniqueConstraint
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()


class ResourceOwner(Base):

    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    name = Column(String)
    email = Column(String)
    password = Column(String)


class Consumer(Base):

    __tablename__ = "consumers"

    id = Column(Integer, primary_key=True)
    consumer_key = Column(String)
    consumer_secret = Column(String)
    rsa_key = Column(String)
    user = Column(Integer, ForeignKey("users.id"))
    realm = Column(String)
    redirect_uri = Column(String)
    application_title = Column(String)
    application_description = Column(String)
    application_uri = Column(String)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    modified_at = Column(DateTime, default=datetime.datetime.utcnow)


class RequestToken(Base):

    __tablename__ = "request_tokens"

    id = Column(Integer, primary_key=True)
    consumer = Column(Integer, ForeignKey("consumers.id"))
    user = Column(Integer, ForeignKey("users.id"))
    realm = Column(String)
    redirect_uri = Column(String)
    request_token = Column(String)
    request_token_secret = Column(String)
    verifier = Column(String)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    modified_at = Column(DateTime, default=datetime.datetime.utcnow)


class AccessToken(Base):

    __tablename__ = "access_tokens"

    id = Column(Integer, primary_key=True)
    consumer = Column(Integer, ForeignKey("consumers.id"))
    user = Column(Integer, ForeignKey("users.id"))
    realm = Column(String)
    access_token = Column(String)
    access_token_secret = Column(String)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    modified_at = Column(DateTime, default=datetime.datetime.utcnow)


class Nonce(Base):

    __tablename__ = "nonce"

    id = Column(Integer, primary_key=True)
    consumer_key = Column('consumer_key', String)
    token = Column('token', String)
    timestamp = Column('timestamp', Integer)
    nonce = Column('nonce', String)

    UniqueConstraint('consumer_key', 'token', 'timestamp', 'nonce')
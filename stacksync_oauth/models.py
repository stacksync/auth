import datetime
from sqlalchemy import Column, BigInteger, Integer, String, ForeignKey, DateTime, UniqueConstraint
from sqlalchemy.dialects.postgresql.base import UUID
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()


class ResourceOwner(Base):

    __tablename__ = "user1"

    id = Column(UUID, primary_key=True)
    name = Column(String)
    email = Column(String)
    swift_user = Column(String)
    swift_account = Column(String)
    quota_used_real = Column(BigInteger)
    quota_used_logical = Column(BigInteger)
    quota_limit = Column(Integer)


class Consumer(Base):

    __tablename__ = "oauth1_consumers"

    id = Column(Integer, primary_key=True)
    consumer_key = Column(String)
    consumer_secret = Column(String)
    rsa_key = Column(String)
    user = Column(UUID, ForeignKey("user1.id"))
    realm = Column(String)
    redirect_uri = Column(String)
    application_title = Column(String)
    application_description = Column(String)
    application_uri = Column(String)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    modified_at = Column(DateTime, default=datetime.datetime.utcnow)


class RequestToken(Base):

    __tablename__ = "oauth1_request_tokens"

    id = Column(Integer, primary_key=True)
    consumer = Column(Integer, ForeignKey("oauth1_consumers.id"))
    user = Column(UUID, ForeignKey("user1.id"))
    realm = Column(String)
    redirect_uri = Column(String)
    request_token = Column(String)
    request_token_secret = Column(String)
    verifier = Column(String)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    modified_at = Column(DateTime, default=datetime.datetime.utcnow)


class AccessToken(Base):

    __tablename__ = "oauth1_access_tokens"

    id = Column(Integer, primary_key=True)
    consumer = Column(Integer, ForeignKey("oauth1_consumers.id"))
    user = Column(UUID, ForeignKey("user1.id"))
    realm = Column(String)
    access_token = Column(String)
    access_token_secret = Column(String)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    modified_at = Column(DateTime, default=datetime.datetime.utcnow)


class Nonce(Base):

    __tablename__ = "oauth1_nonce"

    id = Column(Integer, primary_key=True)
    consumer_key = Column('consumer_key', String)
    token = Column('token', String)
    timestamp = Column('timestamp', Integer)
    nonce = Column('nonce', String)

    UniqueConstraint('consumer_key', 'token', 'timestamp', 'nonce')

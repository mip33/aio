import atexit
import uuid

from sqlalchemy import Column, Integer, String, ForeignKey, DateTime, func, create_engine
from sqlalchemy.orm import declarative_base, relationship, sessionmaker
from sqlalchemy_utils import EmailType, UUIDType

SQ_DSN = 'sqlite:///aihttp_app.db'
engine = create_engine(SQ_DSN)
Base = declarative_base(bind=engine)


class UserModel(Base):
    __tablename__ = 'app_user'
    id = Column(Integer, primary_key=True, autoincrement=True)
    email = Column(EmailType, unique=True, nullable=False, index=True)
    password_hash = Column(String, unique=True, nullable=False)


class TokenModel(Base):
    __tablename__ = 'app_token'
    id = Column(UUIDType, primary_key=True, default=uuid.uuid4)
    creation_time = Column(DateTime, server_default=func.now())
    user_id = Column(Integer, ForeignKey('app_user.id', ondelete='CASCADE'), nullable=False)
    user = relationship('UserModel', backref='tokens')


class Advertisement(Base):
    __tablename__ = 'app_advertisement'
    id = Column(Integer, primary_key=True, autoincrement=True)
    title = Column(String, nullable=False)
    description = Column(String, nullable=True)
    created_at = Column(DateTime, server_default=func.now())
    owner = Column(Integer, ForeignKey('app_user.id', ondelete='CASCADE'), nullable=False)
    user = relationship('UserModel', backref='advertisements')


Base.metadata.create_all()
Session = sessionmaker(bind=engine)
atexit.register(engine.dispose)

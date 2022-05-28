from sqlalchemy import Boolean, Column, ForeignKey, Integer, String, DateTime
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.postgresql import UUID
from .database import Base
from datetime import datetime,timezone
import uuid

# start = datetime.now(timezone.utc)

class Auth(Base):
    __tablename__ = "auth"

    id = Column(UUID(as_uuid=True), primary_key=True, index=True, server_default='uuid_generate_v4()')
    username = Column(String, unique=True)
    password = Column(String)
    account_active = Column(Boolean, default=False)
    account_admin = Column(Boolean, default=False)
    created_date = Column(DateTime(timezone=True), server_default=func.now())

    #userlogs = relationship("Logging", back_populates="userlogs")

class Logging(Base):
    __tablename__ = "logging"

    id = Column(UUID(as_uuid=True), primary_key=True, index=True, server_default='uuid_generate_v4()')
    username = Column(String, ForeignKey(Auth.username))
    page = Column(String)
    data_size = Column(Integer)
    endpoint = Column(String)
    parameters = Column(String)
    user_agent = Column(String)
    ip_address = Column(String)
    query_date = Column(DateTime(timezone=True), server_default=func.now())

    #userlogs = relationship("Auth",back_populates="userlogs")

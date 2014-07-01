from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session
from sqlalchemy.orm.session import sessionmaker
from stacksync_oauth.models import Base

dbsession = scoped_session(sessionmaker())
#engine = create_engine("sqlite:///foo.db", echo=False)
engine = create_engine("postgresql://stacksync_user:stacksync@localhost/stacksync")
dbsession.configure(bind=engine, autoflush=False, expire_on_commit=False)

#Base.metadata.drop_all(engine)
Base.metadata.create_all(engine)
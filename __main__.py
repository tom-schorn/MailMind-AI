from sqlalchemy import create_engine
from Entities import init_db


def start_flask():
    pass





if __name__ == "__main__":
    engine = create_engine("sqlite:///storage.db", echo=True)
    init_db(engine)

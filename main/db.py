import sqlite3
from datetime import datetime

import click
from flask import current_app, g


def get_db(): # Obtém a conexão com o banco de dados
    if 'db' not in g:
        g.db = sqlite3.connect(
            current_app.config['DATABASE'],
            detect_types=sqlite3.PARSE_DECLTYPES
        )
        g.db.row_factory = sqlite3.Row

    return g.db

def close_db(e=None): # Fecha a conexão com o banco de dados
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db(): # Inicializa o banco de dados
    db = get_db()
    with current_app.open_resource('todo.sql') as f:
        db.executescript(f.read().decode('utf8'))

@click.command('init-db') # Comando para inicializar o banco de dados
def init_db_command():
    init_db()
    click.echo('Banco de dados inicializado.')

sqlite3.register_converter( # Registra um conversor para o tipo de dado timestamp
    "timestamp", lambda v: datetime.fromisoformat(v.decode())
)

def init_app(app): # Inicializa a aplicação com as configurações do banco de dados
    app.teardown_appcontext(close_db)
    app.cli.add_command(init_db_command)

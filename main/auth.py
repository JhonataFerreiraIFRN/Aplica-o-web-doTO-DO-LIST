import functools

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)

from werkzeug.security import check_password_hash, generate_password_hash

from main.db import get_db

bp = Blueprint('auth', __name__, url_prefix='/auth')

@bp.route('/registro', methods=('GET', 'POST'))
def registro():
    if request.method == 'POST':
        usuario = request.form['usuario']
        email = request.form['email']
        senha = request.form['senha']
        db = get_db()
        erro = None

        if not usuario:
            erro = 'Usuário é obrigatório.'
        elif not email:
            erro = 'Email é obrigatório.'
        elif not senha:
            erro = 'Senha é obrigatória.'

        if erro is None:
            try:
                db.execute(
                    'INSERT INTO USUARIOS (nome, email, senha) VALUES (?, ?, ?)',
                    (usuario, email, generate_password_hash(senha))
                )
                db.commit()
            except db.IntegrityError:
                erro = f'Usuário {usuario} já existe.'
            else:
                return redirect(url_for('auth.login'))
        flash(erro)
    return render_template('auth/registro.html')

@bp.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        usuario = request.form['usuario']
        senha = request.form['senha']
        db = get_db()
        erro = None
        usuario_db = db.execute(
            'SELECT Id_Usuario, nome, senha FROM USUARIOS WHERE nome = ?',
            (usuario,)
        ).fetchone()
        if usuario_db is None:
            erro = 'Usuário não encontrado.'
        elif not check_password_hash(usuario_db['senha'], senha):
            erro = 'Senha incorreta.'
        
        if erro is None:
            session.clear()
            session['Id_Usuario'] = usuario_db['Id_Usuario']
            return redirect(url_for('index'))
        
        flash(erro)
    
    return render_template('auth/login.html')

@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('Id_Usuario')

    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute(
            'SELECT * FROM USUARIOS WHERE Id_Usuario = ?', (user_id,)
        ).fetchone()

@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('auth.login'))

def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))
        return view(**kwargs)

    return wrapped_view

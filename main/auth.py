import functools

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)

from werkzeug.security import check_password_hash, generate_password_hash

from main.db import get_db

bp = Blueprint('auth', __name__, url_prefix='/auth')

def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))
        return view(**kwargs)

    return wrapped_view


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

@bp.route('/usuario', methods=('GET', 'POST'))
@login_required
def lista_usuarios():
    db = get_db()
    usuarios = db.execute(
        'SLECT Id_Usuario, nome, email FROM USUARIOS ORDER BY Id_Usuario DESC'
    ).fetchall()
    return render_template('auth/usuarios.html', usuarios=usuarios)
@bp.route('/usuario/<int:id_usuario>/editar', methods=('GET', 'POST'))
@login_required
def editar_usuario(id_usuario):
    if request.method == 'POST':
        nome = request.form['nome']
        email = request.form['email']
        senha = request.form['senha']
        db = get_db()
        erro = None

        if not nome:
            erro = 'Nome é obrigatório.'
        elif not email:
            erro = 'Email é obrigatório.'

        if erro is None:
            try:
                db.execute(
                    'UPDATE USUARIOS SET nome = ?, email = ?, senha = ? WHERE Id_Usuario = ?',
                    (nome, email, generate_password_hash(senha), id_usuario)
                )
                db.commit()
            except db.IntegrityError:
                erro = f'Usuário {nome} já existe.'
            else:
                return redirect(url_for('auth.lista_usuarios')) # redireciona para a lista de usuários
        flash(erro)
    return render_template('auth/editar_usuario.html', id_usuario=id_usuario)

@bp.route('/usuario/<int:id_usuario>/excluir', methods=('POST',))
@login_required
def excluir_usuario(id_usuario):
    db = get_db()
    db.execute('DELETE FROM USUARIOS WHERE Id_Usuario = ?', (id_usuario,))
    db.commit()
    return redirect(url_for('auth.lista_usuarios'))

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


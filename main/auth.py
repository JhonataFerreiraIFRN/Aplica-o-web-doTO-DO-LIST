import functools

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)

from werkzeug.security import check_password_hash, generate_password_hash

from main.db import get_db

bp = Blueprint('auth', __name__, url_prefix='/auth')

def login_required(view): # esta função é um decorador que verifica se o usuário está logado antes de acessar uma rota protegida
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))
        return view(**kwargs)

    return wrapped_view


@bp.route('/registro', methods=('GET', 'POST')) 
def registro():
    if request.method == 'POST':
        # Coleta os dados do formulário de registro atráves do request
        usuario = request.form['usuario'] 
        email = request.form['email']
        senha = request.form['senha']
        db = get_db() # obtém a conexão com o banco de dados
        erro = None
        # Verifica se os campos obrigatórios foram preenchidos
        if not usuario:
            erro = 'Usuário é obrigatório.'
        elif not email:
            erro = 'Email é obrigatório.'
        elif not senha:
            erro = 'Senha é obrigatória.'
        # Verifica se o usuário já existe no banco de dados
        if erro is None:
            try: # tenta inserir o novo usuário no banco de dados
                db.execute(
                    'INSERT INTO USUARIOS (nome, email, senha) VALUES (?, ?, ?)', # comando SQL para inserir o usuário
                    (usuario, email, generate_password_hash(senha)) # gera o hash da senha antes de armazená-la, basicamente, para segurança pois senhas não devem ser armazenadas em texto simples, ou seja , ela é criptografada
                )
                db.commit() # confirma a transação no banco de dados
            except db.IntegrityError:
                erro = f'Usuário {usuario} já existe.'
            else: # se não houver erro, redireciona para a página de login
                return redirect(url_for('auth.login'))
        flash(erro)
    return render_template('auth/registro.html')

@bp.route('/usuario', methods=('GET', 'POST')) # lista os usuários cadastrados e permite a criação de novos usuários
@login_required
def lista_usuarios():
    db = get_db() # obtém a conexão com o banco de dados
    usuarios = db.execute(
        'SELECT Id_Usuario, nome, email FROM USUARIOS ORDER BY Id_Usuario DESC' # comando SQL para selecionar todos os usuários
    ).fetchall() # busca todos os usuários cadastrados no banco de dados, se fosse fatchone, retornaria apenas o primeiro usuário encontrado
    return render_template('auth/usuario.html', usuarios=usuarios)


@bp.route('/usuario/<int:id_usuario>/editar', methods=('GET', 'POST')) # esta rota permite editar os dados de um usuário específico, pois o id_usuario é passado como parâmetro na URL
@login_required
def editar_usuario(id_usuario): # obtém o id do usuário a ser editado
    if request.method == 'POST':
        nome = request.form['nome']
        email = request.form['email']
        senha = request.form['senha']
        db = get_db()
        erro = None
        # Verifica se os campos obrigatórios foram preenchidos
        if not nome:
            erro = 'Nome é obrigatório.'
        elif not email:
            erro = 'Email é obrigatório.'

        if erro is None:
            try:
                db.execute(
                    'UPDATE USUARIOS SET nome = ?, email = ?, senha = ? WHERE Id_Usuario = ?', # comando SQL para atualizar os dados do usuário
                    (nome, email, generate_password_hash(senha), id_usuario)
                )
                db.commit() # confirma a transação no banco de dados
            except db.IntegrityError:
                erro = f'Usuário {nome} já existe.'
            else:
                return redirect(url_for('auth.lista_usuarios')) # redireciona para a lista de usuários
        flash(erro)
    return render_template('auth/editar_usuario.html', id_usuario=id_usuario)

@bp.route('/usuario/<int:id_usuario>/excluir', methods=('POST',))
@login_required
def excluir_usuario(id_usuario):
    db = get_db() # obtém a conexão com o banco de dados
    db.execute('DELETE FROM USUARIOS WHERE Id_Usuario = ?', (id_usuario,)) # comando SQL para excluir o usuário com o id especificado, pegado pela URL
    db.commit() # confirma a transação no banco de dados
    return redirect(url_for('auth.lista_usuarios')) # redireciona para a lista de usuários

@bp.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        usuario = request.form['usuario']
        senha = request.form['senha']
        db = get_db()
        erro = None
        usuario_db = db.execute(
            'SELECT Id_Usuario, nome, senha FROM USUARIOS WHERE nome = ?',
            (usuario,) # busca o usuário no banco de dados pelo nome, se o usuário não existir, retorna None
        ).fetchone() # fetchone() retorna apenas uma linha do resultado da consulta, ou seja, o primeiro usuário encontrado com o nome especificado
        if usuario_db is None:
            erro = 'Usuário não encontrado.'
        elif not check_password_hash(usuario_db['senha'], senha): # verifica se a senha fornecida corresponde à senha armazenada no banco de dados
            # check_password_hash compara a senha fornecida com o hash da senha armazenada no banco de dados
            erro = 'Senha incorreta.'
        
        if erro is None:
            session.clear() # limpa a sessão atual para garantir que não haja dados antigos
            session['Id_Usuario'] = usuario_db['Id_Usuario'] # armazena o id do usuário na sessão, para que possa ser usado em outras partes da aplicação
            return redirect(url_for('index')) 
        
        flash(erro)
    
    return render_template('auth/login.html')

@bp.before_app_request # esta função é executada antes de cada requisição para verificar se o usuário está logado
def load_logged_in_user(): 
    user_id = session.get('Id_Usuario') # obtém o id do usuário da sessão, se não houver usuário logado, user_id será None

    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute(
            'SELECT * FROM USUARIOS WHERE Id_Usuario = ?', (user_id,)
        ).fetchone() # busca o usuário no banco de dados pelo id armazenado na sessão e atribui o resultado a g.user, que é um objeto global usado para armazenar dados durante a requisição atual

@bp.route('/logout') # rota para fazer logout do usuário
def logout():
    session.clear()
    return redirect(url_for('auth.login'))


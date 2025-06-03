# To-Do List com Flask

Este projeto é uma aplicação de **lista de tarefas (To-Do List)** construída com **Flask**, utilizando **SQLite** como banco de dados e **Bootstrap** para o layout responsivo.  
Cada usuário possui suas próprias listas e tarefas, com autenticação segura.

---

## Funcionalidades

- Cadastro e login de usuários
- Logout com segurança
- Criação, edição e remoção de listas de tarefas
- Adição, modificação e exclusão de tarefas em cada lista
- Marcação de tarefas como concluídas
- Interface amigável e responsiva com Bootstrap

---

## Estrutura do Banco de Dados

- **USUARIOS**: Id_Usuario, nome, email, senha
- **LISTAS_DE_TAREFAS**: Id_Lista, nome, Id_Usuario
- **TAREFAS**: id_tarefa, descricao, concluida, data_criacao, data_conclusao, Id_lista

---

## Como executar o projeto

1. **Clone o repositório**
    ```bash
    git clone https://github.com/seu-usuario/to-do-list-flask.git
    cd to-do-list-flask
    ```

2. **Crie e ative um ambiente virtual**
    ```bash
    python -m venv .venv
    .venv\Scripts\activate
    ```

3. **Inicialize o banco de dados**
    ```bash
    flask --app main init-db
    ```

4. **Inicie o servidor**
    ```bash
    flask --app main run
    ```

5. **Acesse a aplicação em:**  
    [http://127.0.0.1:5000](http://127.0.0.1:5000)

---

## Estrutura de Diretórios

``` bash

├── instance/
│
├── main/
│ ├── pycache/
│ ├── init.py
│ ├── auth.py
│ ├── db.py
│ ├── list.py
│ ├── templates/
│ │ ├── base.html
│ │ ├── auth/
│ │ │ ├── login.html
│ │ │ └── registro.html
│ │ └── list/
│ │ ├── criar.html
│ │ ├── criar_tarefa.html
│ │ ├── editar_lista.html
│ │ ├── editar_tarefa.html
│ │ ├── index.html
│ │ └── tarefas.html
│
├── todo.sql
├── hello.py
├── .gitignore
└── README.md


```


---

## Informações Adicionais

- O projeto utiliza Blueprints do Flask para modularizar as rotas de autenticação e tarefas.
- A variável `g.user` armazena os dados do usuário logado durante as requisições.
- O banco de dados é gerenciado via SQLite e pode ser criado com o script `todo.sql`.

---

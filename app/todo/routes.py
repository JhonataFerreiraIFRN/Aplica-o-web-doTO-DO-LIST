from flask import render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from app import db
from app.todo import bp
from app.todo.forms import TaskListForm, TaskForm
from app.models import TaskList, Task
from datetime import datetime

@bp.route('/lists')
@login_required
def lists():
    user_lists = current_user.lists.all()
    return render_template('todo/lists.html', title='Minhas Listas', lists=user_lists)

@bp.route('/list/<int:list_id>')
@login_required
def list_detail(list_id):
    task_list = TaskList.query.get_or_404(list_id)
    if task_list.owner != current_user:
        abort(403)
    return render_template('todo/list_detail.html', list=task_list)

@bp.route('/create_list', methods=['GET', 'POST'])
@login_required
def create_list():
    form = TaskListForm()
    if form.validate_on_submit():
        task_list = TaskList(
            title=form.title.data,
            description=form.description.data,
            owner=current_user
        )
        db.session.add(task_list)
        db.session.commit()
        flash('Sua lista foi criada!')
        return redirect(url_for('todo.lists'))
    return render_template('todo/edit_list.html', title='Criar Lista', form=form)

@bp.route('/edit_list/<int:list_id>', methods=['GET', 'POST'])
@login_required
def edit_list(list_id):
    task_list = TaskList.query.get_or_404(list_id)
    if task_list.owner != current_user:
        abort(403)
    form = TaskListForm()
    if form.validate_on_submit():
        task_list.title = form.title.data
        task_list.description = form.description.data
        db.session.commit()
        flash('Sua lista foi atualizada!')
        return redirect(url_for('todo.lists'))
    elif request.method == 'GET':
        form.title.data = task_list.title
        form.description.data = task_list.description
    return render_template('todo/edit_list.html', title='Editar Lista', form=form)

@bp.route('/delete_list/<int:list_id>', methods=['POST'])
@login_required
def delete_list(list_id):
    task_list = TaskList.query.get_or_404(list_id)
    if task_list.owner != current_user:
        abort(403)
    db.session.delete(task_list)
    db.session.commit()
    flash('Sua lista foi deletada!')
    return redirect(url_for('todo.lists'))

@bp.route('/list/<int:list_id>/create_task', methods=['GET', 'POST'])
@login_required
def create_task(list_id):
    task_list = TaskList.query.get_or_404(list_id)
    if task_list.owner != current_user:
        abort(403)
    form = TaskForm()
    if form.validate_on_submit():
        task = Task(
            title=form.title.data,
            description=form.description.data,
            due_date=form.due_date.data,
            list_id=list_id
        )
        db.session.add(task)
        db.session.commit()
        flash('Sua tarefa foi adicionada!')
        return redirect(url_for('todo.list_detail', list_id=list_id))
    return render_template('todo/edit_task.html', title='Adicionar Tarefa', form=form)

@bp.route('/task/<int:task_id>')
@login_required
def task_detail(task_id):
    task = Task.query.get_or_404(task_id)
    if task.list.owner != current_user:
        abort(403)
    return render_template('todo/task_detail.html', task=task)

@bp.route('/edit_task/<int:task_id>', methods=['GET', 'POST'])
@login_required
def edit_task(task_id):
    task = Task.query.get_or_404(task_id)
    if task.list.owner != current_user:
        abort(403)
    form = TaskForm()
    if form.validate_on_submit():
        task.title = form.title.data
        task.description = form.description.data
        task.due_date = form.due_date.data
        task.completed = form.completed.data
        db.session.commit()
        flash('Sua tarefa foi atualizada!')
        return redirect(url_for('todo.list_detail', list_id=task.list_id))
    elif request.method == 'GET':
        form.title.data = task.title
        form.description.data = task.description
        form.due_date.data = task.due_date
        form.completed.data = task.completed
    return render_template('todo/edit_task.html', title='Editar Tarefa', form=form)

@bp.route('/delete_task/<int:task_id>', methods=['POST'])
@login_required
def delete_task(task_id):
    task = Task.query.get_or_404(task_id)
    if task.list.owner != current_user:
        abort(403)
    list_id = task.list_id
    db.session.delete(task)
    db.session.commit()
    flash('Sua tarefa foi deletada!')
    return redirect(url_for('todo.list_detail', list_id=list_id))
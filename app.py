# app.py
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import uuid
import os
from sqlalchemy.orm import relationship
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your_fallback_key_here')

basedir = os.path.abspath(os.path.dirname(__file__))

if os.environ.get('RENDER'):
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///expenses.db'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

group_members = db.Table('group_members',
    db.Column('user_id', db.String(36), db.ForeignKey('user.id'), primary_key=True),
    db.Column('group_id', db.String(36), db.ForeignKey('group.id'), primary_key=True)
)

expense_participants = db.Table('expense_participants',
    db.Column('user_id', db.String(36), db.ForeignKey('user.id'), primary_key=True),
    db.Column('expense_id', db.String(36), db.ForeignKey('expense.id'), primary_key=True)
)

class User(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    groups = relationship('Group', secondary=group_members, back_populates='members')
    expenses_paid = relationship('Expense', backref='payer', foreign_keys='Expense.payer_id')
    def __repr__(self):
        return f'<User {self.username}>'

class Group(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(100), nullable=False)
    creator_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    members = relationship('User', secondary=group_members, back_populates='groups')
    expenses = relationship('Expense', backref='group', cascade='all, delete-orphan')
    balances = relationship('Balance', backref='group', cascade='all, delete-orphan')
    def __repr__(self):
        return f'<Group {self.name}>'
    def created_at_formatted(self):
        return self.created_at.strftime('%Y-%m-%d')

class Expense(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    description = db.Column(db.String(200), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    payer_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    group_id = db.Column(db.String(36), db.ForeignKey('group.id'), nullable=False)
    is_settlement = db.Column(db.Boolean, default=False)
    receiver_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=True)
    participants = relationship('User', secondary=expense_participants)
    def __repr__(self):
        return f'<Expense {self.description}>'
    def date_formatted(self):
        return self.date.strftime('%Y-%m-%d')

class Balance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    group_id = db.Column(db.String(36), db.ForeignKey('group.id'), nullable=False)
    amount = db.Column(db.Float, default=0.0)
    user = relationship('User')
    __table_args__ = (db.UniqueConstraint('user_id', 'group_id', name='unique_user_group'),)
    def __repr__(self):
        return f'<Balance {self.user_id} - {self.amount}>'

with app.app_context():
    db.create_all()

@app.template_filter('format_date')
def format_date(value):
    if isinstance(value, datetime):
        return value.strftime('%Y-%m-%d')
    return value

@app.route('/')
def home():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    user = User.query.get(user_id)
    if not user:
        session.pop('user_id', None)
        return redirect(url_for('login'))
    return render_template('home.html', user=user, groups=user.groups)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            return redirect(url_for('home'))
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists')
            return render_template('register.html')
        existing_email = User.query.filter_by(email=email).first()
        if existing_email:
            flash('Email already exists')
            return render_template('register.html')
        new_user = User(
            username=username,
            password=generate_password_hash(password),
            email=email
        )
        db.session.add(new_user)
        db.session.commit()
        session['user_id'] = new_user.id
        return redirect(url_for('home'))
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

@app.route('/create_group', methods=['GET', 'POST'])
def create_group():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    user = User.query.get(user_id)
    if not user:
        session.pop('user_id', None)
        return redirect(url_for('login'))
    if request.method == 'POST':
        group_name = request.form.get('group_name')
        new_group = Group(
            name=group_name,
            creator_id=user_id
        )
        new_group.members.append(user)
        db.session.add(new_group)
        db.session.commit()
        balance = Balance(user_id=user_id, group_id=new_group.id, amount=0.0)
        db.session.add(balance)
        db.session.commit()
        return redirect(url_for('view_group', group_id=new_group.id))
    return render_template('create_group.html')

@app.route('/group/<group_id>')
def view_group(group_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    group = Group.query.get(group_id)
    if not group:
        flash('Group not found')
        return redirect(url_for('home'))
    user = User.query.get(user_id)
    if user not in group.members:
        flash('You are not a member of this group')
        return redirect(url_for('home'))
    expenses = Expense.query.filter_by(group_id=group_id).order_by(Expense.date.desc()).all()
    balances = Balance.query.filter_by(group_id=group_id).all()
    balance_dict = {balance.user_id: balance.amount for balance in balances}
    debts = calculate_debts(balance_dict)
    members_dict = {member.id: member for member in group.members}
    return render_template('view_group.html',
                          group=group,
                          expenses=expenses,
                          members=members_dict,
                          balances=balance_dict,
                          debts=debts,
                          current_user_id=user_id)

@app.route('/group/<group_id>/add_member', methods=['POST'])
def add_member(group_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    group = Group.query.get(group_id)
    if not group:
        flash('Group not found')
        return redirect(url_for('home'))
    username = request.form.get('username')
    user_to_add = User.query.filter_by(username=username).first()
    if not user_to_add:
        flash('User not found')
        return redirect(url_for('view_group', group_id=group_id))
    if user_to_add not in group.members:
        group.members.append(user_to_add)
        balance = Balance(user_id=user_to_add.id, group_id=group_id, amount=0.0)
        db.session.add(balance)
        db.session.commit()
        flash(f'Added {username} to the group')
    else:
        flash(f'{username} is already in the group')
    return redirect(url_for('view_group', group_id=group_id))

@app.route('/group/<group_id>/add_expense', methods=['POST'])
def add_expense(group_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    group = Group.query.get(group_id)
    if not group:
        flash('Group not found')
        return redirect(url_for('home'))
    description = request.form.get('description')
    amount = float(request.form.get('amount'))
    payer_id = request.form.get('payer_id')
    payer = User.query.get(payer_id)
    if not payer or payer not in group.members:
        flash('Invalid payer')
        return redirect(url_for('view_group', group_id=group_id))

    new_expense = Expense(
        description=description,
        amount=amount,
        payer_id=payer_id,
        group_id=group_id
    )

    for member in group.members:
        new_expense.participants.append(member)

    db.session.add(new_expense)

    split_amount = amount / len(group.members) # Split based on *current* members
    for member in group.members:
        balance = Balance.query.filter_by(user_id=member.id, group_id=group_id).first()
        if not balance:
            balance = Balance(user_id=member.id, group_id=group_id, amount=0.0)
            db.session.add(balance)
        if member.id == payer_id:
            balance.amount += (amount - split_amount)
        else:
            balance.amount -= split_amount

    db.session.commit()
    flash('Expense added successfully')
    return redirect(url_for('view_group', group_id=group_id))

@app.route('/group/<group_id>/settle', methods=['POST'])
def settle_debt(group_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    group = Group.query.get(group_id)
    if not group:
        flash('Group not found')
        return redirect(url_for('home'))
    from_id = request.form.get('from_id')
    to_id = request.form.get('to_id')
    amount = float(request.form.get('amount'))
    from_user = User.query.get(from_id)
    to_user = User.query.get(to_id)
    if not from_user or not to_user or from_user not in group.members or to_user not in group.members:
        flash('Invalid users')
        return redirect(url_for('view_group', group_id=group_id))

    from_balance = Balance.query.filter_by(user_id=from_id, group_id=group_id).first()
    to_balance = Balance.query.filter_by(user_id=to_id, group_id=group_id).first()
    if not from_balance or not to_balance:
        flash('Balance records not found')
        return redirect(url_for('view_group', group_id=group_id))

    from_balance.amount += amount
    to_balance.amount -= amount

    settlement = Expense(
        description=f"Settlement: {from_user.username} paid {to_user.username}",
        amount=amount,
        payer_id=from_id,
        receiver_id=to_id,
        group_id=group_id,
        is_settlement=True
    )
    settlement.participants.append(from_user)
    settlement.participants.append(to_user)

    db.session.add(settlement)
    db.session.commit()
    flash('Payment recorded successfully')
    return redirect(url_for('view_group', group_id=group_id))

@app.route('/group/<group_id>/expense/<expense_id>/delete', methods=['POST'])
def delete_expense(group_id, expense_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    group = Group.query.get(group_id)
    if not group:
        flash('Group not found')
        return redirect(url_for('home'))
    expense = Expense.query.get(expense_id)
    if not expense:
        flash('Expense not found')
        return redirect(url_for('view_group', group_id=group_id))
    if expense.group_id != group_id:
        flash('Expense does not belong to this group')
        return redirect(url_for('view_group', group_id=group_id))
    current_user_id = session['user_id']
    if group.creator_id != current_user_id: 
        flash('Only group creator can delete expenses.')
        return redirect(url_for('view_group', group_id=group_id))

    if expense.is_settlement:
        payer = User.query.get(expense.payer_id)
        receiver = User.query.get(expense.receiver_id)
        from_balance = Balance.query.filter_by(user_id=expense.payer_id, group_id=group_id).first()
        to_balance = Balance.query.filter_by(user_id=expense.receiver_id, group_id=group_id).first()
        if from_balance and payer in expense.participants: # Double check participant
            from_balance.amount -= expense.amount
        if to_balance and receiver in expense.participants: # Double check participant
            to_balance.amount += expense.amount
    else:
        split_amount = expense.amount / len(expense.participants) # Split by participants
        payer_id = expense.payer_id
        for participant in expense.participants: # Iterate participants, not current members
            balance = Balance.query.filter_by(user_id=participant.id, group_id=group_id).first()
            if participant.id == payer_id:
                balance.amount -= (expense.amount - split_amount)
            else:
                balance.amount += split_amount

    db.session.delete(expense)
    db.session.commit()
    flash('Expense deleted successfully')
    return redirect(url_for('view_group', group_id=group_id))

@app.route('/group/<group_id>/delete', methods=['POST'])
def delete_group(group_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    group = Group.query.get(group_id)
    if not group:
        flash('Group not found')
        return redirect(url_for('home'))
    if session['user_id'] != group.creator_id:
        flash('Only group creator can delete the group.')
        return redirect(url_for('view_group', group_id=group_id))

    db.session.delete(group)
    db.session.commit()
    flash('Group deleted successfully.')
    return redirect(url_for('home'))


@app.route('/group/<group_id>/member/<member_id>/remove', methods=['POST'])
def remove_member(group_id, member_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    group = Group.query.get(group_id)
    if not group:
        flash('Group not found')
        return redirect(url_for('home'))
    if session['user_id'] != group.creator_id:
        flash('Only group creator can remove members.')
        return redirect(url_for('view_group', group_id=group_id))
    user_to_remove = User.query.get(member_id)
    if not user_to_remove:
        flash('User not found')
        return redirect(url_for('view_group', group_id=group_id))
    if user_to_remove.id == group.creator_id:
        flash('Cannot remove the group creator.')
        return redirect(url_for('view_group', group_id=group_id))
    if user_to_remove not in group.members:
        flash('User is not a member of the group.')
        return redirect(url_for('view_group', group_id=group_id))
    group.members.remove(user_to_remove)
    balance_to_delete = Balance.query.filter_by(user_id=member_id, group_id=group_id).first()
    if balance_to_delete:
        db.session.delete(balance_to_delete)
    db.session.commit()
    flash(f'{user_to_remove.username} removed from the group.')
    return redirect(url_for('view_group', group_id=group_id))

@app.route('/group/<group_id>/leave', methods=['POST'])
def leave_group(group_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    group = Group.query.get(group_id)
    if not group:
        flash('Group not found')
        return redirect(url_for('home'))
    
    user = User.query.get(user_id)
    if user not in group.members:
        flash('You are not a member of this group')
        return redirect(url_for('home'))
    
    if user.id == group.creator_id:
        flash('Group creator cannot leave. Delete the group instead.')
        return redirect(url_for('view_group', group_id=group_id))

    group.members.remove(user)
    
    balance = Balance.query.filter_by(user_id=user_id, group_id=group_id).first()
    if balance:
        db.session.delete(balance)
    
    db.session.commit()
    flash('You have left the group')
    return redirect(url_for('home'))


def calculate_debts(balances):
    debts = []
    positives = [(member, balance) for member, balance in balances.items() if balance > 0]
    negatives = [(member, -balance) for member, balance in balances.items() if balance < 0]
    positives.sort(key=lambda x: x[1], reverse=True)
    negatives.sort(key=lambda x: x[1], reverse=True)
    i, j = 0, 0
    while i < len(negatives) and j < len(positives):
        debtor, debt_amount = negatives[i]
        creditor, credit_amount = positives[j]
        amount = min(debt_amount, credit_amount)
        if amount > 0.01:
            debts.append({
                'from': debtor,
                'to': creditor,
                'amount': round(amount, 2)
            })
        negatives[i] = (debtor, debt_amount - amount)
        positives[j] = (creditor, credit_amount - amount)
        if negatives[i][1] < 0.01:
            i += 1
        if positives[j][1] < 0.01:
            j += 1
    return debts

if __name__ == '__main__':
    app.run(debug=False)
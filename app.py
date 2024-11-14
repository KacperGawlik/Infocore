from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_migrate import Migrate

app = Flask(__name__)

# Konfiguracja bazy danych
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'supersecretkey'

# Inicjalizacja baz danych, haszowania, migracji i logowania
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
migrate = Migrate(app, db)

# Model użytkownika
from flask_login import UserMixin

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    is_active = db.Column(db.Boolean, default=True)  # Kolumna is_active

    def __repr__(self):
        return f"User('{self.username}')"

# Ładowanie użytkownika po ID
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Strona logowania
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            print(f"Zalogowany użytkownik: {user.username}")
            print(f"Sesja po logowaniu: {session}")
            return redirect(url_for('home'))
        else:
            flash('Niepoprawna nazwa użytkownika lub hasło', 'danger')

    return render_template('login.html')

# Strona główna
from flask import session

@app.route('/')
@login_required
def home():
    print(f'Session data: {session}')  # Sprawdzamy zawartość sesji
    return render_template('home.html', username=current_user.username)



# Strona wylogowania
@app.route('/logout')
@login_required
def logout():
    logout_user()  # Wylogowanie użytkownika
    return redirect(url_for('login'))

# Uruchomienie aplikacji
if __name__ == '__main__':
    app.run(debug=True)

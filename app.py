from datetime import datetime
import pandas as pd
from io import BytesIO
from flask import Flask, render_template, request, redirect, url_for, jsonify, send_file, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from flask_migrate import Migrate

# Flask app initialisieren
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///warenwirtschaft.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key'

db = SQLAlchemy(app)
migrate = Migrate(app, db, render_as_batch=True)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Datenbankmodelle
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), nullable=False, default='user')  # 'admin' oder 'user'

    # Beziehung zu Shops (Many-to-Many)
    shops = db.relationship('Shop', secondary='user_shops', backref=db.backref('users', lazy='dynamic'))

class OrderTracking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_number = db.Column(db.String(100), nullable=False, unique=True)
    order_date = db.Column(db.Date, nullable=False)
    location = db.Column(db.String(200), nullable=False)
    order_details = db.Column(db.Text, nullable=False)
    info = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(50), nullable=False, default='Open')  # Open, Delivered, Canceled
    delivery_date = db.Column(db.Date, nullable=True)
    cancel_reason = db.Column(db.Text, nullable=True)

class Shop(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    stocks = db.relationship('Stock', backref='shop', lazy=True)

class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)

class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)

class Stock(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    shop_id = db.Column(db.Integer, db.ForeignKey('shop.id'), nullable=False)
    item_id = db.Column(db.Integer, db.ForeignKey('item.id'), nullable=False)
    quantity = db.Column(db.Integer, default=0)

# Many-to-Many-Tabelle für Benutzer und Shops
user_shops = db.Table('user_shops',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('shop_id', db.Integer, db.ForeignKey('shop.id'), primary_key=True)
)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Rollenbasierte Zugriffskontrolle
def admin_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if current_user.role != 'admin':
            flash("Keine Berechtigung für diese Aktion.")
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# Routen
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Login fehlgeschlagen. Prüfen Sie Ihre Zugangsdaten.')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard', methods=['GET'])
@login_required
def dashboard():
    categories = Category.query.all()
    items = Item.query.all()
    shops = Shop.query.all()

    matrix = {}
    for category in categories:
        matrix[category.name] = {}
        category_items = [item for item in items if item.category_id == category.id]
        for item in category_items:
            matrix[category.name][item.name] = {}
            for shop in shops:
                stock = Stock.query.filter_by(shop_id=shop.id, item_id=item.id).first()
                matrix[category.name][item.name][shop.name] = stock.quantity if stock else 0

    return render_template('dashboard.html', matrix=matrix, shops=shops)

@app.route('/export_dashboard', methods=['GET'])
@login_required
def export_dashboard():
    categories = Category.query.all()
    items = Item.query.all()
    shops = Shop.query.all()

    # Bestandsdaten vorbereiten
    data = []
    for category in categories:
        category_items = [item for item in items if item.category_id == category.id]
        for item in category_items:
            row = {'Warengruppe': category.name, 'Artikel': item.name}
            for shop in shops:
                stock = Stock.query.filter_by(shop_id=shop.id, item_id=item.id).first()
                row[shop.name] = stock.quantity if stock else 0
            data.append(row)

    # Erstellen eines DataFrames aus den Daten
    df = pd.DataFrame(data)

    # Erstellen eines Excel-Exports im Speicher
    output = BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, index=False, sheet_name='Bestände')

    output.seek(0)

    # Excel-Datei senden
    return send_file(output, as_attachment=True, download_name="dashboard_bestände.xlsx", mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")

@app.route('/shops', methods=['GET', 'POST'])
@login_required
def shops():
    if request.method == 'POST':
        shop_name = request.form['name']
        new_shop = Shop(name=shop_name)
        db.session.add(new_shop)
        db.session.commit()
        return redirect(url_for('shops'))
    shops = Shop.query.all()
    return render_template('shops.html', shops=shops)

@app.route('/shops/<int:shop_id>', methods=['GET'])
@login_required
def shop_details(shop_id):
    shop = Shop.query.get_or_404(shop_id)
    categories = Category.query.all()
    items = Item.query.all()

    # Bestandsliste vorbereiten
    stocks = {item.id: 0 for item in items}
    for stock in Stock.query.filter_by(shop_id=shop_id).all():
        stocks[stock.item_id] = stock.quantity

    # Artikel nach Kategorien gruppieren
    items_grouped = {}
    for category in categories:
        category_items = [
            {"item": item, "quantity": stocks[item.id]}
            for item in items if item.category_id == category.id
        ]
        items_grouped[category.name] = category_items

    return render_template('shop_details.html', shop=shop, items_grouped=items_grouped)

@app.route('/shops/delete/<int:shop_id>', methods=['POST'])
@login_required
def delete_shop(shop_id):
    try:
        # Shop und zugehörige Stocks laden
        shop = Shop.query.get_or_404(shop_id)
        stocks = Stock.query.filter_by(shop_id=shop_id).all()
        
        # Zuerst alle Stocks löschen
        for stock in stocks:
            db.session.delete(stock)
        
        # Shop löschen
        db.session.delete(shop)
        db.session.commit()
        
        return jsonify({'success': True, 'message': f'Shop {shop_id} erfolgreich gelöscht'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/shops/adjust_stock', methods=['POST'])
@login_required
def adjust_stock():
    data = request.get_json()
    shop_id = data.get('shop_id')
    item_id = data.get('item_id')
    adjustment = data.get('adjustment', 0)

    if not all([shop_id, item_id, adjustment]):
        return jsonify({'error': 'Ungültige Anfrageparameter'}), 400

    stock = Stock.query.filter_by(shop_id=shop_id, item_id=item_id).first()
    if not stock:
        stock = Stock(shop_id=shop_id, item_id=item_id, quantity=0)
        db.session.add(stock)

    stock.quantity += adjustment
    if stock.quantity < 0:
        stock.quantity = 0
    db.session.commit()

    return jsonify({'new_quantity': stock.quantity})

@app.route('/shops/add_stock', methods=['POST'])
@login_required
def add_stock():
    data = request.get_json()
    shop_id = data.get('shop_id')
    item_id = data.get('item_id')
    adjustment = data.get('adjustment', 0)

    if not all([shop_id, item_id, adjustment]):
        return jsonify({'error': 'Ungültige Anfrageparameter'}), 400

    stock = Stock.query.filter_by(shop_id=shop_id, item_id=item_id).first()
    if not stock:
        stock = Stock(shop_id=shop_id, item_id=item_id, quantity=0)
        db.session.add(stock)

    stock.quantity += adjustment
    db.session.commit()

    return jsonify({'new_quantity': stock.quantity})

@app.route('/categories', methods=['GET', 'POST'])
@login_required
def categories():
    if request.method == 'POST':
        category_name = request.form['name']
        if not category_name:
            return "Warengruppen-Name darf nicht leer sein.", 400
        new_category = Category(name=category_name)
        db.session.add(new_category)
        db.session.commit()
        return redirect(url_for('categories'))
    categories = Category.query.all()
    return render_template('categories.html', categories=categories)

@app.route('/categories/edit/<int:category_id>', methods=['GET', 'POST'])
@login_required
def edit_category(category_id):
    category = Category.query.get_or_404(category_id)
    if request.method == 'POST':
        category.name = request.form['name']
        db.session.commit()
        return redirect(url_for('categories'))
    return render_template('edit_category.html', category=category)

@app.route('/categories/delete/<int:category_id>', methods=['POST'])
@login_required
def delete_category(category_id):
    category = Category.query.get_or_404(category_id)
    db.session.delete(category)
    db.session.commit()
    return redirect(url_for('categories'))

@app.route('/items', methods=['GET', 'POST'])
@login_required
def items():
    if request.method == 'POST':
        item_name = request.form['name']
        category_id = request.form['category_id']
        if not item_name or not category_id:
            return "Artikelname und Warengruppe dürfen nicht leer sein.", 400
        new_item = Item(name=item_name, category_id=category_id)
        db.session.add(new_item)
        db.session.commit()
        return redirect(url_for('items'))
    categories = Category.query.all()
    items_grouped = {}
    for category in categories:
        items_grouped[category.name] = Item.query.filter_by(category_id=category.id).all()
    return render_template('items.html', items_grouped=items_grouped, categories=categories)

@app.route('/items/edit/<int:item_id>', methods=['GET', 'POST'])
@login_required
def edit_item(item_id):
    item = Item.query.get_or_404(item_id)
    categories = Category.query.all()
    if request.method == 'POST':
        item.name = request.form['name']
        item.category_id = request.form['category_id']
        db.session.commit()
        return redirect(url_for('items'))
    return render_template('edit_item.html', item=item, categories=categories)

@app.route('/items/delete/<int:item_id>', methods=['POST'])
@login_required
def delete_item(item_id):
    item = Item.query.get_or_404(item_id)
    db.session.delete(item)
    db.session.commit()
    return redirect(url_for('items'))

@app.route('/orders', methods=['GET', 'POST'])
@login_required
def orders():
    if request.method == 'POST':
        order_number = request.form['order_number']
        order_date = request.form['order_date']
        location = request.form['location']
        order_details = request.form['order_details']

        try:
            order_date = datetime.strptime(order_date, '%Y-%m-%d').date()
            new_order = OrderTracking(
                order_number=order_number,
                order_date=order_date,
                location=location,
                order_details=order_details,
            )
            db.session.add(new_order)
            db.session.commit()
            flash("Bestellung erfolgreich hinzugefügt.")
        except Exception as e:
            db.session.rollback()
            flash(f"Fehler beim Hinzufügen der Bestellung: {e}")

        return redirect(url_for('orders'))

    open_orders = OrderTracking.query.filter_by(status='Open').all()
    archived_orders = OrderTracking.query.filter(OrderTracking.status.in_(['Delivered', 'Canceled'])).all()

    return render_template('orders.html', open_orders=open_orders, archived_orders=archived_orders)

@app.route('/orders/<int:order_id>/deliver', methods=['POST'])
@login_required
def deliver_order(order_id):
    order = OrderTracking.query.get_or_404(order_id)
    delivery_date = request.form.get('delivery_date')
    if not delivery_date:
        flash("Lieferdatum erforderlich.")
        return redirect(url_for('orders'))
    try:
        order.delivery_date = datetime.strptime(delivery_date, '%Y-%m-%d').date()
        order.status = 'Delivered'
        db.session.commit()
        flash("Bestellung als geliefert markiert.")
    except ValueError:
        flash("Ungültiges Datumsformat.")
    return redirect(url_for('orders'))

@app.route('/orders/<int:order_id>/cancel', methods=['POST'])
@login_required
def cancel_order(order_id):
    order = OrderTracking.query.get_or_404(order_id)
    cancel_reason = request.form.get('cancel_reason')
    if not cancel_reason:
        flash("Stornierungsgrund erforderlich.")
        return redirect(url_for('orders'))
    try:
        order.status = 'Canceled'
        order.cancel_reason = cancel_reason
        db.session.commit()
        flash("Bestellung storniert.")
    except Exception as e:
        db.session.rollback()
        flash(f"Fehler beim Stornieren der Bestellung: {e}")
    return redirect(url_for('orders'))

@app.route('/orders/<int:order_id>/update_info', methods=['POST'])
@login_required
def update_order_info(order_id):
    order = OrderTracking.query.get_or_404(order_id)
    new_info = request.form.get('info')
    if not new_info:
        flash("Info erforderlich.")
        return redirect(url_for('orders'))
    try:
        order.info = new_info
        db.session.commit()
        flash("Info aktualisiert.")
    except Exception as e:
        db.session.rollback()
        flash(f"Fehler beim Aktualisieren der Info: {e}")
    return redirect(url_for('orders'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(email=email, password=hashed_password, role='user')  # Standardrolle ist 'user'
        try:
            db.session.add(new_user)
            db.session.commit()
            flash("Benutzer erfolgreich registriert.")
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash(f"Fehler bei der Registrierung: {e}")
    return render_template('register.html')

@app.route('/admin/users', methods=['GET', 'POST'])
@login_required
@admin_required
def manage_users():
    if request.method == 'POST':
        user_id = request.form.get('user_id')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role')
        user = User.query.get(user_id)
        if user:
            user.email = email
            if password:
                user.password = generate_password_hash(password, method='pbkdf2:sha256')
            user.role = role
            db.session.commit()
        return redirect(url_for('manage_users'))
    
    users = User.query.all()
    return render_template('manage_users.html', users=users)

@app.route('/admin/users/delete/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    return redirect(url_for('manage_users'))

@app.route('/admin/users/add', methods=['GET', 'POST'])
@login_required
@admin_required
def add_user():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']
        
        # Benutzer erstellen und in die Datenbank einfügen
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(email=email, password=hashed_password, role=role)
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('manage_users'))  # Nach dem Hinzufügen des Benutzers zurück zur Benutzerverwaltung

    return render_template('add_user.html')  # Template für das Hinzufügen eines Benutzers anzeigen

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Nur für Entwicklungszwecke!
        # Standard-Admin-Benutzer hinzufügen
        if not User.query.filter_by(email='admin@datapoynt.de').first():
            admin_user = User(
                email='admin@datapoynt.de',
                password=generate_password_hash('admin', method='pbkdf2:sha256'),
                role='admin'
            )
            db.session.add(admin_user)
            db.session.commit()
    app.run(host='0.0.0.0', port=5001, debug=True)
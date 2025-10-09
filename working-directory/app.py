from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from functools import wraps
from decimal import Decimal, InvalidOperation
from datetime import datetime, time

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:password@localhost/stockcraft_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your-secret-key'

db = SQLAlchemy(app)

login_manager = LoginManager(app)


@login_manager.user_loader
def load_user(user_id: str):
    return User.query.get(int(user_id))


login_manager.login_view = "login"

def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated:
            return login_manager.unauthorized()
        if not current_user.is_admin:
            flash("Admin access required.", "error")
            return redirect(url_for("home"))
        return f(*args, **kwargs)
    return wrapper


class User(UserMixin, db.Model):
    __tablename__ = "user"
    user_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    lastname = db.Column(db.String(120), nullable=False)
    firstname = db.Column(db.String(120), nullable=False)
    password = db.Column(db.String(200), nullable=False)

    is_admin = db.Column(db.Boolean, default=False)

    orders = db.relationship("Order", backref="user", lazy=True)
    portfolios = db.relationship("Portfolio", backref="user", lazy=True)
    cash_account = db.relationship(
        "CashAccount", backref="user", uselist=False)

    @property
    def id(self):
        return self.user_id

    def set_password(self, raw_password: str):
        self.password = generate_password_hash(raw_password)

    def check_password(self, raw_password: str) -> bool:
        return check_password_hash(self.password, raw_password)


class Stock(db.Model):
    __tablename__ = "stock"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    stock_ticker = db.Column(db.String(80), unique=True, nullable=False)
    company = db.Column(db.String(120), unique=True, nullable=False)
    initial_price = db.Column(db.Float, nullable=False)
    available_stocks = db.Column(db.Integer, nullable=False)

    orders = db.relationship("Order", backref="stock", lazy=True)
    portfolios = db.relationship("Portfolio", backref="stock", lazy=True)


class Order(db.Model):
    __tablename__ = "order"
    order_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey(
        "user.user_id"), nullable=False)
    stock_id = db.Column(db.Integer, db.ForeignKey(
        "stock.id"), nullable=False)
    quantity = db.Column(db.Integer, nullable=False, default=1)


class Transaction(db.Model):
    __tablename__ = "transaction"
    transaction_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    order_id = db.Column(db.Integer, db.ForeignKey("order.order_id"), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.user_id"), nullable=False)
    stock_id = db.Column(db.Integer, db.ForeignKey("stock.id"), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)


class MarketSetting(db.Model):
    __tablename__ = "market_setting"
    id = db.Column(db.Integer, primary_key=True)
    hours = db.Column(db.String(50), nullable=False, default="8:00 AM-5:00 PM")
    schedule = db.Column(db.String(500), nullable=True, default="")


def parse_time_string(value: str):
    value = value.strip()
    if not value:
        raise ValueError
    try:
        return datetime.strptime(value, "%I:%M %p").time()
    except ValueError:
        return datetime.strptime(value, "%H:%M").time()


def parse_market_hours(hours: str):
    simple_hours = hours.split("-", 1)
    if len(simple_hours) != 2:
        return time(8, 0), time(17, 0)
    try:
        start_time = parse_time_string(simple_hours[0])
        end_time = parse_time_string(simple_hours[1])
        return start_time, end_time
    except ValueError:
        return time(8, 0), time(17, 0)


def get_closed_dates(schedule: str):
    if not schedule:
        return set()
    dates = set()
    for piece in schedule.split(","):
        cleaned = piece.strip()
        if cleaned:
            dates.add(cleaned)
    return dates


def get_market_context():
    setting = MarketSetting.query.first()
    if not setting:
        setting = MarketSetting(hours="8:00 AM-5:00 PM", schedule="")
        db.session.add(setting)
        db.session.commit()
    now = datetime.now()
    open_time, close_time = parse_market_hours(setting.hours or "")
    closed_dates = get_closed_dates(setting.schedule or "")
    today = now.strftime("%Y-%m-%d")
    current_time = now.time()

    market_open = open_time <= current_time <= close_time
    if today in closed_dates:
        market_open = False

    formatted_dates = sorted(list(closed_dates))
    display_hours = f"{open_time.strftime('%I:%M %p')} to {close_time.strftime('%I:%M %p')}"

    return {
        "setting": setting,
        "market_open": market_open,
        "closed_today": today in closed_dates,
        "open_time": open_time,
        "close_time": close_time,
        "closed_dates": closed_dates,
        "closed_dates_formatted": formatted_dates,
        "display_hours": display_hours,
    }

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        lastname = request.form.get("lastname", "").strip()
        firstname = request.form.get("firstname", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")
        

        if User.query.filter_by(username=username).first():
            flash("Username already taken.", "error")
            return render_template("signup.html")
        
        existing_email = User.query.filter_by(email=email).first()
        if existing_email:
            flash("Email address already in use.", "error")
            return render_template("signup.html")

        if password != confirm_password:
            flash("Passwords do not match.", "error")
            return render_template("signup.html")

        if not all([username, email, lastname, firstname, password]):
            flash("All fields are required.", "error")
            return render_template("signup.html")

        first_user= (User.query.count() == 0)
        
        u = User(username=username, email=email,
                 lastname=lastname, firstname=firstname,
                 is_admin=first_user)
        
        u.set_password(password)
        try:
            db.session.add(u)
            db.session.commit()
            flash("Account created. Please log in.", "success")
            return redirect(url_for("login"))
        except Exception as e:
            db.session.rollback()
            flash(f"Error creating account: {e}", "error")
            return render_template("signup.html")
    return render_template("signup.html")


@app.route("/admin/add_admin", methods=["GET", "POST"])
@login_required
@admin_required
def add_admin():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        lastname = request.form.get("lastname", "").strip()
        firstname = request.form.get("firstname", "").strip()
        password = request.form.get("password", "")
        confirm_password=request.form.get("confirm_password","")
        

        if User.query.filter_by(username=username).first():
            flash("Username already taken.", "error")
            return render_template("add_admin.html")
        
        existing_email = User.query.filter_by(email=email).first()
        if existing_email:
            flash("Email address already in use.", "error")
            return render_template("add_admin.html")
        
        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template("add_admin.html")

        if not all([username, email, lastname, firstname, password]):
            flash("All fields are required.", "error")
            return render_template("add_admin.html")

        is_admin = bool(request.form.get("is_admin"))
        u = User(username=username, email=email,
                 lastname=lastname, firstname=firstname,
                 is_admin=True)
        
        u.set_password(password)
        try:
            db.session.add(u)
            db.session.commit()
            flash("Account created. Please log in.", "success")
            return redirect(url_for("login"))
        except Exception as e:
            db.session.rollback()
            flash(f"Error creating account: {e}", "error")
            return render_template("add_admin.html")
    return render_template("add_admin.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            flash(f"Welcome back, {user.username}!", "success")
            if user.is_admin:
                return redirect(url_for("admin_dashboard"))
            return redirect(url_for("portfolio_index"))
        flash("Invalid username or password.", "error")
    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out.", "success")
    return redirect(url_for("home"))


@app.route("/admin/dashboard")
@login_required
@admin_required
def admin_dashboard():
    users = User.query.order_by(User.user_id.desc()).all()
    stocks = Stock.query.all()
    orders = Order.query.order_by(Order.order_id.desc()).all()
    market = get_market_context()
    return render_template("admin.html", users=users, stocks=stocks, orders=orders, market=market)


@app.route("/admin/market-settings", methods=["POST"])
@login_required
@admin_required
def update_market_settings():
    market = get_market_context()
    setting = market["setting"]
    form_type = request.form.get("form_type")
    if form_type == "hours":
        hours = (request.form.get("market_hours") or "").strip()
        if hours:
            parts = hours.split("-", 1)
            if len(parts) != 2:
                flash("Incorrect format.", "danger")
                return redirect(url_for("admin_dashboard"))
            try:
                parse_time_string(parts[0])
                parse_time_string(parts[1])
            except ValueError:
                flash("Incorrect format.", "danger")
                return redirect(url_for("admin_dashboard"))
            setting.hours = hours
        else:
            flash("Hours value required.", "danger")
            return redirect(url_for("admin_dashboard"))
    elif form_type == "schedule":
        schedule = (request.form.get("market_schedule") or "").strip()
        if schedule:
            lines = []
            for raw in schedule.replace(",", "\n").splitlines():
                value = raw.strip()
                if not value:
                    continue
                parsed = None
                for fmt in ("%B %d %Y", "%b %d %Y", "%Y-%m-%d"):
                    try:
                        parsed = datetime.strptime(value, fmt)
                        break
                    except ValueError:
                        continue
                if parsed:
                    lines.append(parsed.strftime("%Y-%m-%d"))
                else:
                    lines.append(value)
            setting.schedule = "\n".join(lines)
        else:
            setting.schedule = ""
    db.session.commit()
    flash("Market settings updated.", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/orders", methods=["GET"])
@login_required
def orders():
    stocks = Stock.query.order_by(Stock.stock_ticker.asc()).all()
    acct = CashAccount.query.filter_by(user_id=current_user.user_id).first()
    positions = Portfolio.query.filter_by(user_id=current_user.user_id).all()

    user_orders = Order.query.filter_by(user_id=current_user.user_id).order_by(
        Order.order_id.desc()).limit(20).all()

    market = get_market_context()
    return render_template("orders.html", stocks=stocks, acct=acct, positions=positions, user_orders=user_orders, market=market)


@app.route("/orders/add", methods=["POST"])
@login_required
def add_order():    
    try:
        market = get_market_context()
        if not market["market_open"]:
            flash("Market is closed.", "danger")
            return redirect(url_for("orders"))
        stock_id = int(request.form.get("stock_id", 0))
        quantity = int(request.form.get("quantity", 0))
        user_id = current_user.user_id
        
        if quantity <= 0:
            flash("Quantity invalid!", "danger")
            return redirect(url_for("orders"))

        stock=Stock.query.get(stock_id)
        if not stock:
            flash("Stock not found.", "danger")
            return redirect(url_for("orders"))

        if stock.available_stocks < quantity:   
            flash(f"Not enough stocks available. Available: {stock.available_stocks}", "danger")
            return redirect(url_for("orders"))
        
        stock.available_stocks = stock.available_stocks - quantity

        o = Order(user_id=user_id, stock_id=stock_id, quantity=quantity)
        db.session.add(o)
        db.session.commit()
        t = Transaction(
            order_id=o.order_id,
            user_id=user_id,
            stock_id=stock_id,
            quantity=quantity
        )
        db.session.add(t)

        pos = Portfolio.query.filter_by(user_id=user_id, stock_id=stock_id).first()
        if pos:
            pos.quantity = pos.quantity + quantity
        else:
            pos = Portfolio(user_id=user_id, stock_id=stock_id, quantity=quantity)
            db.session.add(pos)


        db.session.commit()
        flash(f"Order added and position added to portfolio! {quantity} shares of {stock.company} purchased. Remaining: {stock.available_stocks}", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error adding order: {e}")

    return redirect(url_for("orders"))


@app.route("/orders/sell/<int:order_id>")
@login_required
def sell_order(order_id):
    try:
        market = get_market_context()
        if not market["market_open"]:
            flash("Market is closed.", "danger")
            return redirect(url_for("orders"))
        o = Order.query.get(order_id)
        if not o:
            flash("Order not found.")
        else:
            db.session.delete(o)
            db.session.commit()
            flash(f"Order {order_id} sold.")
    except Exception as e:
        db.session.rollback()
        flash(f"Error selling order: {e}")
    return redirect(url_for("orders"))


@app.route("/users")
@login_required
@admin_required
def users():
    rows = User.query.order_by(User.user_id.desc()).all()
    return render_template("user.html", users=rows)


@app.route('/add_user/<string:username>/<string:email>/<string:lastname>/<string:firstname>/<string:password>')
@login_required
@admin_required
def add_user(username, email, lastname, firstname, password):
    if not username or not email:
        flash('Both username and email are required!', 'error')
        return redirect(url_for('users'))

    new_user = User(username=username, email=email,
                    lastname=lastname, firstname=firstname)
    new_user.set_password(password)
    try:
        db.session.add(new_user)
        db.session.commit()
        flash(f'User {username} added successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error adding user: {str(e)}', 'error')
    return redirect(url_for('users'))


@app.route('/stocks')
@login_required
def stocks():
    stocks = Stock.query.all()
    return render_template('stocks.html', stocks=stocks)


@app.route('/add_stock', methods=['POST'])
@login_required
@admin_required
def add_stock():
    if not current_user.is_admin:
        flash("Admin access required.", "error")
        return redirect(url_for('stocks'))
     
    stock_ticker = request.form.get('stock_ticker')
    company = request.form.get('company')
    initial_price = request.form.get('initial_price', type=float)
    available_stocks = request.form.get('available_stocks', type=int)

    if not (stock_ticker and company and initial_price and available_stocks):
        flash('Missing required information!', 'error')
        return redirect(url_for('stocks'))
    
    if Stock.query.filter_by(stock_ticker=stock_ticker).first():
        flash("Stock already exists.", "error")
        return redirect(url_for("stocks"))

    new_stock = Stock(stock_ticker=stock_ticker,
                      company=company,
                      initial_price=initial_price,
                      available_stocks=available_stocks,
                      )

    try:
        db.session.add(new_stock)
        db.session.commit()
        flash(f'Stock {new_stock.id} added successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error adding stock: {str(e)}', 'error')

    return redirect(url_for('stocks'))


class CashAccount(db.Model):
    __tablename__ = "cash_account"
    cash_account_id = db.Column(
        db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey(
        "user.user_id"), unique=True, nullable=False)
    current_balance = db.Column(db.Numeric(
        14, 2), nullable=False, default=0.00)
    updated_at = db.Column(
        db.TIMESTAMP,
        server_default=db.func.current_timestamp(),
        onupdate=db.func.current_timestamp(),
        nullable=False,
    )


class Portfolio(db.Model):
    __tablename__ = "portfolio"
    holding_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.user_id"), nullable=False)
    stock_id = db.Column(db.Integer, db.ForeignKey("stock.id"), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    updated_at = db.Column(
        db.TIMESTAMP,
        server_default=db.func.current_timestamp(),
        onupdate=db.func.current_timestamp(),
        nullable=False,
    )

    __table_args__ = (db.UniqueConstraint(
        "user_id", "stock_id", name="uq_portfolio_user_stock"),)


with app.app_context():
    db.create_all()
    setting = MarketSetting.query.first()
    if not setting:
        setting = MarketSetting(hours="8 a.m.-5 p.m.", schedule="")
        db.session.add(setting)
        db.session.commit()


@app.route("/portfolio")
@login_required
def portfolio_index():
    
    return redirect(url_for("portfolio", user_id=current_user.user_id))


@app.route("/portfolio/<int:user_id>")
def portfolio(user_id):
    user = User.query.get_or_404(user_id)
    acct = CashAccount.query.filter_by(user_id=user_id).first()
    positions = Portfolio.query.filter_by(user_id=user_id).all()
    market = get_market_context()
    return render_template("portfolio.html", user=user, acct=acct, positions=positions, market=market)



@app.route('/add_cash/<int:user_id>/<float:amount>')
def add_cash(user_id, amount):
    if amount <= 0:
        flash('Amount must be greater than $0.00.', 'error')
        return redirect(url_for('portfolio', user_id=user_id))
    acct = CashAccount.query.filter_by(user_id=user_id).first()
    if not acct:
        acct = CashAccount(user_id=user_id, current_balance=amount)
        db.session.add(acct)
    else:
        acct.current_balance = acct.current_balance + amount
    db.session.commit()
    flash(f'Added ${amount:.2f} to cash account.', 'success')
    return redirect(url_for('portfolio', user_id=user_id))


@app.route('/withdraw_cash/<int:user_id>/<float:amount>')
def withdraw_cash(user_id, amount):
    if amount <= 0:
        flash('Amount must be greater than $0.00.', 'error')
        return redirect(url_for('portfolio', user_id=user_id))
    acct = CashAccount.query.filter_by(user_id=user_id).first()
    if acct and acct.current_balance >= amount:
        acct.current_balance = acct.current_balance - amount
        db.session.commit()
        flash(f'Withdrew ${amount:.2f} from cash account.', 'success')
    else:
        flash('Insufficient funds or no account.', 'error')
    return redirect(url_for('portfolio', user_id=user_id))


@app.route('/add_position/<int:user_id>/<int:stock_id>/<int:quantity>')
def add_position(user_id, stock_id, quantity):
    pos = Portfolio.query.filter_by(user_id=user_id, stock_id=stock_id).first()
    if pos:
        pos.quantity = pos.quantity + quantity
    else:
        pos = Portfolio(user_id=user_id, stock_id=stock_id, quantity=quantity)
        db.session.add(pos)
    db.session.commit()
    flash(f'Position updated for stock {stock_id}.', 'success')
    return redirect(url_for('portfolio', user_id=user_id))


@app.route('/sell_position/<int:holding_id>', methods=["POST"])
@login_required
def sell_position(holding_id):
    try:
        market = get_market_context()
        if not market["market_open"]:
            flash("Market is closed.", "danger")
            return redirect(url_for("portfolio", user_id=current_user.user_id))

        quantity = int(request.form.get("quantity", 0)) 

        pos = Portfolio.query.filter_by(holding_id=holding_id, user_id=current_user.user_id).first_or_404()

        if quantity <= 0 or quantity > pos.quantity:
            flash('Invalid amount!', "danger")
            return redirect(url_for('portfolio', user_id=current_user.user_id))

        stock = Stock.query.get(pos.stock_id)
        if not stock:
            flash("Stock not found.", "danger")
            return redirect(url_for("portfolio", user_id=current_user.user_id))

        stock.available_stocks = stock.available_stocks + quantity

        transaction=Transaction(
            order_id = None,
            user_id = current_user.user_id,
            stock_id = pos.stock_id,
            quantity = -quantity
        )
        db.session.add(transaction)

        pos.quantity = pos.quantity - quantity
        if pos.quantity == 0:
            db.session.delete(pos)

        
        db.session.commit()
        flash(f"Sold {quantity} shares of {pos.stock.stock_ticker} , {pos.stock.company}! Inventory updated: {stock.available_stocks} shares now available.", "success")
    
    except Exception as e:
        db.session.rollback()
        flash(f"Error selling position: {e}", "danger")

    return redirect(url_for("portfolio", user_id=current_user.user_id))


@app.route("/wallet/deposit", methods=["POST"])
@login_required
def wallet_deposit():
    amount_str = (request.form.get("amount") or "").strip()
    try:
        amount = Decimal(amount_str)
    except (InvalidOperation, ValueError):
        flash("Invalid amount.", "error")
        return redirect(url_for("wallet"))

    if amount <= 0:
        flash("Amount must be greater than $0.00.", "error")
        return redirect(url_for("wallet"))

    acct = CashAccount.query.filter_by(user_id=current_user.user_id).first()
    if not acct:
        acct = CashAccount(user_id=current_user.user_id,
                           current_balance=amount)
        db.session.add(acct)
    else:
        acct.current_balance = acct.current_balance + amount

    db.session.commit()
    flash(f"Deposited ${amount:.2f}.", "success")
    return redirect(url_for("wallet"))


@app.route("/wallet/withdraw", methods=["POST"])
@login_required
def wallet_withdraw():
    amount_str = (request.form.get("amount") or "").strip()
    try:
        amount = Decimal(amount_str)
    except (InvalidOperation, ValueError):
        flash("Invalid amount.", "error")
        return redirect(url_for("wallet"))

    if amount <= 0:
        flash("Amount must be greater than $0.00.", "error")
        return redirect(url_for("wallet"))

    acct = CashAccount.query.filter_by(user_id=current_user.user_id).first()
    if not acct or acct.current_balance < amount:
        flash("Insufficient funds.", "error")
        return redirect(url_for("wallet"))

    acct.current_balance = acct.current_balance - amount
    db.session.commit()
    flash(f"Withdrew ${amount:.2f}.", "success")
    return redirect(url_for("wallet"))


@app.route("/")
def home():

    return render_template("home.html")


@app.route("/admin")
@login_required
@admin_required
def admin():
    stocks = Stock.query.all()
    users = User.query.order_by(User.user_id.desc()).all()
    orders = Order.query.order_by(Order.order_id.desc()).all()
    market = get_market_context()
    return render_template("admin.html", stocks=stocks, users=users, orders=orders, market=market)


@app.route("/wallet", methods=["GET"])
@login_required
def wallet():
    acct = CashAccount.query.filter_by(user_id=current_user.user_id).first()
    return render_template("wallet.html", acct=acct)


if __name__ == "__main__":
    app.run(debug=True)

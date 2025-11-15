from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from functools import wraps
from decimal import Decimal, InvalidOperation
from datetime import datetime, time
import os
import random
from sqlalchemy import inspect, text

app = Flask(__name__, instance_relative_config=True)

db_uri = (
    os.environ.get("SQLALCHEMY_DATABASE_URI")
    or os.environ.get("DATABASE_URL")
)
if not db_uri:
    os.makedirs(app.instance_path, exist_ok=True)
    default_db_path = os.path.join(app.instance_path, "stockcraft.db")
    db_uri = f"sqlite:///{default_db_path}"

app.config["SQLALCHEMY_DATABASE_URI"] = db_uri
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
    current_price = db.Column(db.Float, nullable=True)

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
    transaction_id = db.Column(
        db.Integer, primary_key=True, autoincrement=True)
    order_id = db.Column(db.Integer, db.ForeignKey(
        "order.order_id"), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey(
        "user.user_id"), nullable=False)
    stock_id = db.Column(db.Integer, db.ForeignKey("stock.id"), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)


class MarketSetting(db.Model):
    __tablename__ = "market_setting"
    id = db.Column(db.Integer, primary_key=True)
    hours = db.Column(db.String(50), nullable=False, default="08:00-17:00")
    schedule = db.Column(db.String(500), nullable=True, default="")
    open_days = db.Column(db.String(100), nullable=False,
                          default="Monday,Tuesday,Wednesday,Thursday,Friday")


class ClosureDates(db.Model):
    __tablename__ = "closure_dates"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    closure_date = db.Column(db.Date, nullable=False, unique=True)
    reason = db.Column(db.String(255), nullable=True)
    open_hour = db.Column(db.Integer, nullable=True)
    close_hour = db.Column(db.Integer, nullable=True)
    for_whole_day = db.Column(db.Boolean, nullable=False, default=True)


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
        setting = MarketSetting(hours="08:00-17:00", schedule="")
        db.session.add(setting)
        db.session.commit()

    now = datetime.now()
    weekday = now.strftime("%A")
    open_time, close_time = parse_market_hours(setting.hours or "")
    today = now.date()
    current_hour = now.hour
    current_time = now.time()


    open_days = (setting.open_days or "").split(",")
    market_open = (weekday in open_days) and (
        open_time <= current_time <= close_time)

    closed_today = ClosureDates.query.filter_by(closure_date=today).first()
    if closed_today:
        if closed_today.for_whole_day:
            market_open = False
        elif closed_today.open_hour is not None and closed_today.close_hour is not None:
            market_open = closed_today.open_hour <= current_hour < closed_today.close_hour
        else:
            market_open = False

    display_hours = f"{open_time.strftime('%H:%M')} to {close_time.strftime('%H:%M')}"

    closures = ClosureDates.query.order_by(ClosureDates.closure_date.asc()).all()
    
    formatted_closures = []
    for closure in closures:  
        if closure.for_whole_day:
            desc="Closed whole day"
        elif closure.open_hour is not None and closure.close_hour is not None:
            desc=f"{closure.open_hour:02d}:00 - {closure.close_hour:02d}:00"

        else:
            desc="Partially closed (unspecified hours)"

        formatted_closures.append({
            "id": closure.id,
            "date": closure.closure_date.strftime("%Y-%m-%d"),
            "reason": closure.reason,
            "description": desc,
            "open_hour": closure.open_hour,
            "close_hour": closure.close_hour,
            "for_whole_day": closure.for_whole_day
        })
    

    return {
        "setting": setting,
        "market_open": market_open,
        "open_time": open_time,
        "close_time": close_time,
        "closure_list": formatted_closures,
        "display_hours": display_hours,
    }


@app.route("/update_stock_prices")
def update_stock_prices():
    MU = 0.00005
    SIGMA = 0.0015
    JUMP_PROB = 0.004
    JUMP_SIZE = 0.01

    stocks = Stock.query.all()

    for stock in stocks:
        price = float(stock.current_price or 0) or 100.0
        pct = random.gauss(MU, SIGMA)
        if random.random() < JUMP_PROB:
            pct += random.uniform(-JUMP_SIZE, JUMP_SIZE)
        new_price = price * (1.0 + pct)
        new_price = max(0.01, round(new_price, 2))
        stock.current_price = new_price
        new_price_decimal = to_decimal(new_price)
        for pos in stock.portfolios:
            pos.current_price = new_price_decimal

    db.session.commit()
    return jsonify({stock.stock_ticker: stock.current_price for stock in stocks})


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

        first_user = (User.query.count() == 0)

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
        confirm_password = request.form.get("confirm_password", "")

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
        start_raw = request.form.get("market_start_hour")
        end_raw = request.form.get("market_end_hour")
        if start_raw is None or end_raw is None:
            flash("Start and end hours required.", "danger")
            return redirect(url_for("admin_dashboard"))
        try:
            start_hour = int(start_raw)
            end_hour = int(end_raw)
        except (TypeError, ValueError):
            flash("Hours must be integers in 24-hour format.", "danger")
            return redirect(url_for("admin_dashboard"))
        if not (0 <= start_hour <= 23 and 0 <= end_hour <= 23):
            flash("Hours must be between 0 and 23.", "danger")
            return redirect(url_for("admin_dashboard"))
        if start_hour == end_hour:
            flash("Start and end hours cannot be the same.", "danger")
            return redirect(url_for("admin_dashboard"))
        if start_hour > end_hour:
            flash("Start hour must be before end hour.", "danger")
            return redirect(url_for("admin_dashboard"))
        setting.hours = f"{start_hour:02d}:00-{end_hour:02d}:00"
    elif form_type == "schedule":
        month_raw = request.form.get("schedule_month")
        day_raw = request.form.get("schedule_day")
        year_raw = request.form.get("schedule_year")
        if not all([month_raw, day_raw, year_raw]):
            flash("All date fields required.", "danger")
            return redirect(url_for("admin_dashboard"))
        try:
            month = int(month_raw)
            day = int(day_raw)
            year = int(year_raw)
        except ValueError:
            flash("Date values must be integers.", "danger")
            return redirect(url_for("admin_dashboard"))
        try:
            parsed = datetime(year, month, day)
        except ValueError:
            flash("Invalid date.", "danger")
            return redirect(url_for("admin_dashboard"))
        existing = get_closed_dates(setting.schedule or "")
        existing.add(parsed.strftime("%Y-%m-%d"))
        setting.schedule = "\n".join(sorted(existing))
    db.session.commit()
    flash("Market settings updated.", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/add-closure", methods=["POST"])
@login_required
@admin_required
def add_closure():
    date_str = request.form.get("closure_date")
    reason = request.form.get("reason", "").strip()
    open_hour_int = request.form.get("open_hour")
    close_hour_int = request.form.get("close_hour")
    for_whole_day = request.form.get("for_whole_day") == "on"

    try:
        closure_date = datetime.strptime(date_str, "%Y-%m-%d").date()

    except ValueError:
        flash("Invalid date format.", "danger")
        return redirect(url_for("admin_dashboard"))

    existing_closures = ClosureDates.query.filter_by(
        closure_date=closure_date).first()
    


    open_hour = None
    close_hour = None

    if not for_whole_day and open_hour_int and close_hour_int:
        try:
            open_hour = int(open_hour_int)
            close_hour = int(close_hour_int)
        except ValueError:
            flash("Invalid time format.", "danger")
            return redirect(url_for("admin_dashboard"))

    if existing_closures:
        if (existing_closures.for_whole_day == for_whole_day and 
            (existing_closures.open_hour != open_hour or existing_closures.close_hour != close_hour)):
            open_hour = int(open_hour_int)
            close_hour = int(close_hour_int)
            existing_closures.for_whole_day = for_whole_day
            existing_closures.open_hour = open_hour
            existing_closures.close_hour = close_hour
            db.session.commit()
            flash(f"Updated market closure for {closure_date}.", "success")
            return redirect(url_for("admin_dashboard"))
        if (existing_closures.for_whole_day != for_whole_day and not for_whole_day):
            open_hour = int(open_hour_int)
            close_hour = int(close_hour_int)
            existing_closures.for_whole_day = for_whole_day
            existing_closures.open_hour = open_hour
            existing_closures.close_hour = close_hour
            db.session.commit()
            flash(f"Updated market closure for {closure_date}.", "success")
            return redirect(url_for("admin_dashboard"))
        if (existing_closures.for_whole_day != for_whole_day and for_whole_day):
            existing_closures.for_whole_day = for_whole_day
            existing_closures.open_hour = None
            existing_closures.close_hour = None
            db.session.commit()
            flash(f"Updated market closure for {closure_date}.", "success")
            return redirect(url_for("admin_dashboard"))
        
        else:
            flash(f"Closure already added.", "warning")
            return redirect(url_for("admin_dashboard"))
 

    new_closure = ClosureDates(
        closure_date=closure_date, 
        reason=reason,
        for_whole_day=for_whole_day,
        open_hour=open_hour,
        close_hour=close_hour
        
    )
    db.session.add(new_closure)
    db.session.commit()
    flash(f"Added market closure for {closure_date}.", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/undo-closure/<int:closure>", methods=["POST"])
@login_required
@admin_required
def undo_closure(closure):
    target_closure = ClosureDates.query.get_or_404(closure)
    db.session.delete(target_closure)
    db.session.commit()
    flash(f"Deleted closure on {target_closure.closure_date}.", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/update-market-days", methods=["POST"])
@login_required
@admin_required
def update_market_days():
    market_status = get_market_context()
    setting = market_status["setting"]

    checked_days = request.form.getlist("open_days")
    setting.open_days = ",".join(checked_days)

    db.session.commit()
    flash("Market days updated.", "success")
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

        stock = Stock.query.get(stock_id)
        if not stock:
            flash("Stock not found.", "danger")
            return redirect(url_for("orders"))

        if stock.available_stocks < quantity:
            flash("Not enough available shares.", "danger")
            return redirect(url_for("orders"))

        price_source = stock.current_price if stock.current_price is not None else stock.initial_price
        price = to_decimal(price_source)
        if price <= 0:
            flash("Invalid stock price.", "danger")
            return redirect(url_for("orders"))

        total_cost = (price * Decimal(quantity)).quantize(TWO_PLACES)

        acct = CashAccount.query.filter_by(user_id=user_id).first()
        if not acct:
            acct = CashAccount(
                user_id=user_id, current_balance=Decimal("0.00"))
            db.session.add(acct)
            db.session.flush()

        if to_decimal(acct.current_balance) < total_cost:
            flash("Insufficient funds.", "danger")
            return redirect(url_for("orders"))

        acct.current_balance = (
            to_decimal(acct.current_balance) - total_cost).quantize(TWO_PLACES)
        stock.available_stocks = stock.available_stocks - quantity

        t = Transaction(order_id=None, user_id=user_id,
                        stock_id=stock_id, quantity=quantity)
        db.session.add(t)

        pos = Portfolio.query.filter_by(
            user_id=user_id, stock_id=stock_id).first()
        if pos:
            existing_qty = pos.quantity
            new_total_qty = existing_qty + quantity
            previous_avg = to_decimal(pos.purchase_price)
            previous_cost = (previous_avg * Decimal(existing_qty)).quantize(TWO_PLACES)
            new_cost = (price * Decimal(quantity)).quantize(TWO_PLACES)
            combined_cost = (previous_cost + new_cost).quantize(TWO_PLACES)
            pos.quantity = new_total_qty
            pos.purchase_price = (combined_cost / Decimal(new_total_qty)).quantize(TWO_PLACES)
        else:
            pos = Portfolio(user_id=user_id, stock_id=stock_id,
                            quantity=quantity,
                            purchase_price=price,
                            current_price=price)
            db.session.add(pos)
        pos.current_price = price

        db.session.commit()
        flash(
            f"Bought {quantity} share(s) of {stock.stock_ticker} for ${total_cost}.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error adding order: {e}", "danger")

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
    market = get_market_context()
    return render_template('stocks.html', stocks=stocks, market=market)


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
                      current_price=initial_price
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
    user_id = db.Column(db.Integer, db.ForeignKey(
        "user.user_id"), nullable=False)
    stock_id = db.Column(db.Integer, db.ForeignKey("stock.id"), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    purchase_price = db.Column(db.Numeric(14, 2), nullable=False, default=Decimal("0.00"))
    current_price = db.Column(db.Numeric(14, 2), nullable=False, default=Decimal("0.00"))
    updated_at = db.Column(
        db.TIMESTAMP,
        server_default=db.func.current_timestamp(),
        onupdate=db.func.current_timestamp(),
        nullable=False,
    )

    __table_args__ = (db.UniqueConstraint(
        "user_id", "stock_id", name="uq_portfolio_user_stock"),)


TWO_PLACES = Decimal("0.01")


def to_decimal(value, default=Decimal("0.00")) -> Decimal:
    try:
        return Decimal(str(value))
    except (InvalidOperation, TypeError, ValueError):
        return Decimal(default)


def ensure_portfolio_price_columns():
    inspector = inspect(db.engine)
    columns = {col["name"] for col in inspector.get_columns("portfolio")}
    dialect = db.engine.dialect.name
    numeric_type = "NUMERIC(14, 2)" if dialect == "sqlite" else "DECIMAL(14,2)"
    alter_statements = []
    if "purchase_price" not in columns:
        alter_statements.append(
            f"ALTER TABLE portfolio ADD COLUMN purchase_price {numeric_type} NOT NULL DEFAULT 0"
        )
    if "current_price" not in columns:
        alter_statements.append(
            f"ALTER TABLE portfolio ADD COLUMN current_price {numeric_type} NOT NULL DEFAULT 0"
        )
    if alter_statements:
        with db.engine.begin() as conn:
            for statement in alter_statements:
                conn.execute(text(statement))

    portfolios = Portfolio.query.all()
    updated = False
    for pos in portfolios:
        stock = Stock.query.get(pos.stock_id)
        if not stock:
            continue
        latest_price = to_decimal(
            stock.current_price if stock.current_price is not None else stock.initial_price
        )
        if not pos.purchase_price or to_decimal(pos.purchase_price) <= Decimal("0.00"):
            pos.purchase_price = latest_price
            updated = True
        if not pos.current_price or to_decimal(pos.current_price) != latest_price:
            pos.current_price = latest_price
            updated = True
    if updated:
        db.session.commit()


with app.app_context():
    db.create_all()
    ensure_portfolio_price_columns()
    setting = MarketSetting.query.first()
    if not setting:
        setting = MarketSetting(hours="08:00-17:00", schedule="")
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
    totals = {
        "cost": Decimal("0.00"),
        "value": Decimal("0.00"),
    }
    detailed_positions = []
    for pos in positions:
        purchase_price = to_decimal(pos.purchase_price)
        current_price = to_decimal(pos.current_price if pos.current_price is not None else pos.stock.current_price)
        cost_basis = (purchase_price * Decimal(pos.quantity)).quantize(TWO_PLACES)
        market_value = (current_price * Decimal(pos.quantity)).quantize(TWO_PLACES)
        gain = (market_value - cost_basis).quantize(TWO_PLACES)
        totals["cost"] += cost_basis
        totals["value"] += market_value
        detailed_positions.append(
            {
                "position": pos,
                "purchase_price": purchase_price.quantize(TWO_PLACES),
                "current_price": current_price.quantize(TWO_PLACES),
                "cost_basis": cost_basis,
                "market_value": market_value,
                "gain": gain,
            }
        )
    totals = {key: value.quantize(TWO_PLACES) for key, value in totals.items()}
    totals["gain"] = (totals["value"] - totals["cost"]).quantize(TWO_PLACES)
    market = get_market_context()
    return render_template(
        "portfolio.html",
        user=user,
        acct=acct,
        positions=detailed_positions,
        totals=totals,
        market=market,
    )


@app.route('/add_cash/<int:user_id>/<amount>')
def add_cash(user_id, amount):
    amount_decimal = to_decimal(amount).quantize(TWO_PLACES)
    if amount_decimal <= 0:
        flash('Amount must be greater than $0.00.', 'error')
        return redirect(url_for('portfolio', user_id=user_id))
    acct = CashAccount.query.filter_by(user_id=user_id).first()
    if not acct:
        acct = CashAccount(user_id=user_id, current_balance=amount_decimal)
        db.session.add(acct)
    else:
        current_balance = to_decimal(acct.current_balance).quantize(TWO_PLACES)
        acct.current_balance = (current_balance + amount_decimal).quantize(TWO_PLACES)
    db.session.commit()
    flash(f'Added ${amount_decimal:.2f} to cash account.', 'success')
    return redirect(url_for('portfolio', user_id=user_id))


@app.route('/withdraw_cash/<int:user_id>/<amount>')
def withdraw_cash(user_id, amount):
    amount_decimal = to_decimal(amount).quantize(TWO_PLACES)
    if amount_decimal <= 0:
        flash('Amount must be greater than $0.00.', 'error')
        return redirect(url_for('portfolio', user_id=user_id))
    acct = CashAccount.query.filter_by(user_id=user_id).first()
    if acct:
        current_balance = to_decimal(acct.current_balance).quantize(TWO_PLACES)
    else:
        current_balance = None
    if acct and current_balance is not None and current_balance >= amount_decimal:
        acct.current_balance = (current_balance - amount_decimal).quantize(TWO_PLACES)
        db.session.commit()
        flash(f'Withdrew ${amount_decimal:.2f} from cash account.', 'success')
    else:
        flash('Insufficient funds or no account.', 'error')
    return redirect(url_for('portfolio', user_id=user_id))


@app.route('/add_position/<int:user_id>/<int:stock_id>/<int:quantity>')
@login_required
def add_position(user_id, stock_id, quantity):
    try:
        if user_id != current_user.user_id:
            flash("Unauthorized.", "danger")
            return redirect(url_for('portfolio', user_id=current_user.user_id))

        market = get_market_context()
        if not market["market_open"]:
            flash("Market is closed.", "danger")
            return redirect(url_for("portfolio", user_id=user_id))

        if quantity <= 0:
            flash("Quantity invalid!", "danger")
            return redirect(url_for('portfolio', user_id=user_id))

        stock = Stock.query.get(stock_id)
        if not stock:
            flash("Stock not found.", "danger")
            return redirect(url_for('portfolio', user_id=user_id))

        if stock.available_stocks < quantity:
            flash("Not enough available shares.", "danger")
            return redirect(url_for('portfolio', user_id=user_id))

        price_source = stock.current_price if stock.current_price is not None else stock.initial_price
        price = to_decimal(price_source)
        if price <= 0:
            flash("Invalid stock price.", "danger")
            return redirect(url_for('portfolio', user_id=user_id))

        total_cost = (price * Decimal(quantity)).quantize(TWO_PLACES)

        acct = CashAccount.query.filter_by(user_id=user_id).first()
        if not acct:
            acct = CashAccount(
                user_id=user_id, current_balance=Decimal("0.00"))
            db.session.add(acct)
            db.session.flush()

        if to_decimal(acct.current_balance) < total_cost:
            flash("Insufficient funds.", "danger")
            return redirect(url_for('portfolio', user_id=user_id))

        acct.current_balance = (
            to_decimal(acct.current_balance) - total_cost).quantize(TWO_PLACES)
        stock.available_stocks = stock.available_stocks - quantity

        t = Transaction(order_id=None, user_id=user_id,
                        stock_id=stock_id, quantity=quantity)
        db.session.add(t)

        pos = Portfolio.query.filter_by(
            user_id=user_id, stock_id=stock_id).first()
        if pos:
            existing_qty = pos.quantity
            new_total_qty = existing_qty + quantity
            previous_avg = to_decimal(pos.purchase_price)
            previous_cost = (previous_avg * Decimal(existing_qty)).quantize(TWO_PLACES)
            new_cost = (price * Decimal(quantity)).quantize(TWO_PLACES)
            combined_cost = (previous_cost + new_cost).quantize(TWO_PLACES)
            pos.quantity = new_total_qty
            pos.purchase_price = (combined_cost / Decimal(new_total_qty)).quantize(TWO_PLACES)
        else:
            pos = Portfolio(user_id=user_id, stock_id=stock_id,
                            quantity=quantity,
                            purchase_price=price,
                            current_price=price)
            db.session.add(pos)
        pos.current_price = price

        db.session.commit()
        flash(
            f"Bought {quantity} share(s) of {stock.stock_ticker} for ${total_cost}.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error updating position: {e}", "danger")

    return redirect(url_for('portfolio', user_id=user_id))


@app.route('/sell_position/<int:holding_id>', methods=["POST"])
@login_required
def sell_position(holding_id):
    try:
        market = get_market_context()
        if not market["market_open"]:
            flash("Market is closed.", "danger")
            return redirect(url_for("portfolio", user_id=current_user.user_id))

        pos = Portfolio.query.get(holding_id)
        if not pos or pos.user_id != current_user.user_id:
            flash("Position not found.", "danger")
            return redirect(url_for("portfolio", user_id=current_user.user_id))

        quantity = int(request.form.get("quantity", 0))
        if quantity <= 0 or quantity > pos.quantity:
            flash("Invalid quantity.", "danger")
            return redirect(url_for("portfolio", user_id=current_user.user_id))

        stock = Stock.query.get(pos.stock_id)
        if not stock:
            flash("Stock not found.", "danger")
            return redirect(url_for("portfolio", user_id=current_user.user_id))

        price_source = stock.current_price if stock.current_price is not None else stock.initial_price
        price = to_decimal(price_source)
        if price <= 0:
            flash("Invalid stock price.", "danger")
            return redirect(url_for("portfolio", user_id=current_user.user_id))

        proceeds = (price * Decimal(quantity)).quantize(TWO_PLACES)

        acct = CashAccount.query.filter_by(
            user_id=current_user.user_id).first()
        if not acct:
            acct = CashAccount(user_id=current_user.user_id,
                               current_balance=Decimal("0.00"))
            db.session.add(acct)
            db.session.flush()

        acct.current_balance = (
            to_decimal(acct.current_balance) + proceeds).quantize(TWO_PLACES)
        stock.available_stocks = stock.available_stocks + quantity

        transaction = Transaction(
            order_id=None, user_id=current_user.user_id, stock_id=pos.stock_id, quantity=-quantity)
        db.session.add(transaction)

        pos.quantity = pos.quantity - quantity
        if pos.quantity == 0:
            db.session.delete(pos)
        else:
            pos.current_price = price

        db.session.commit()
        flash(
            f"Sold {quantity} share(s) of {stock.stock_ticker} for ${proceeds}.", "success")
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

@app.context_processor
def display_wallet_balance():
    from flask_login import current_user
    if current_user.is_authenticated:
        acct = CashAccount.query.filter_by(user_id=current_user.id).first()
        if acct:
            return {"wallet_balance": round(float(acct.current_balance), 2)}
    return {"wallet_balance": None}

if __name__ == "__main__":
    app.run(debug=True)

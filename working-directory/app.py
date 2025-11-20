from flask import Flask, render_template, redirect, url_for, flash, request, jsonify, abort
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from functools import wraps
from decimal import Decimal, InvalidOperation
from datetime import datetime, time, date
from sqlalchemy import func, event
import random
from zoneinfo import ZoneInfo
import enum

app = Flask(__name__)

AZ = ZoneInfo("America/Phoenix")

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:password@localhost/stockcraft_db'
#app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://admin:password@ift401capstonedb.cr2yo46oe8hh.us-east-2.rds.amazonaws.com/stockcraft_db'
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


def parse_price_or_fallback(raw_val, fallback: Decimal) -> Decimal:
    try:
        if raw_val is None or str(raw_val).strip() == "":
            return fallback.quantize(Decimal("0.01"))
        return Decimal(str(raw_val)).quantize(Decimal("0.01"))
    except (InvalidOperation, ValueError):
        return fallback.quantize(Decimal("0.01"))


class TimestampMixin(object):
    created_at = db.Column(db.DateTime(timezone=True),
                           server_default=func.now(), nullable=False)
    updated_at = db.Column(db.DateTime(
        timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)


class TransactionType(enum.Enum):
    BUY = "buy"
    SELL = "sell"
    DEPOSIT = "deposit"
    WITHDRAW = "withdraw"


class User(UserMixin, TimestampMixin, db.Model):
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


class Stock(TimestampMixin, db.Model):
    __tablename__ = "stock"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    stock_ticker = db.Column(db.String(80), unique=True, nullable=False)
    company = db.Column(db.String(120), unique=True, nullable=False)
    initial_price = db.Column(db.Float, nullable=False)
    available_stocks = db.Column(db.Integer, nullable=False)
    current_price = db.Column(db.Float, nullable=True)

    day_open = db.Column(db.Float, nullable=True)
    day_high = db.Column(db.Float, nullable=True)
    day_low = db.Column(db.Float, nullable=True)
    day_date = db.Column(db.Date, nullable=True)

    orders = db.relationship("Order", backref="stock", lazy=True)
    portfolios = db.relationship("Portfolio", backref="stock", lazy=True)


if not hasattr(Stock, "day_open"):
    Stock.day_open = db.Column(db.Numeric(14, 2), nullable=True)
if not hasattr(Stock, "day_high"):
    Stock.day_high = db.Column(db.Numeric(14, 2), nullable=True)
if not hasattr(Stock, "day_low"):
    Stock.day_low = db.Column(db.Numeric(14, 2), nullable=True)
if not hasattr(Stock, "day_date"):
    Stock.day_date = db.Column(db.Date, nullable=True)


class Order(TimestampMixin, db.Model):
    __tablename__ = "order"
    order_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey(
        "user.user_id"), nullable=False)
    stock_id = db.Column(db.Integer, db.ForeignKey(
        "stock.id"), nullable=False)
    quantity = db.Column(db.Integer, nullable=False, default=1)


class Transaction(TimestampMixin, db.Model):
    __tablename__ = "transaction"
    __table_args__ = {"extend_existing": True}

    transaction_id = db.Column(
        db.Integer, primary_key=True)

    order_id = db.Column(db.Integer, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey(
        'user.user_id'), nullable=False)
    stock_id = db.Column(db.Integer, db.ForeignKey('stock.id'), nullable=True)

    quantity = db.Column(db.Integer, nullable=False)

    price = db.Column(db.Numeric(10, 2), nullable=False)
    transaction_type = db.Column(db.Enum(TransactionType), nullable=False)
    timestamp = db.Column(db.DateTime(timezone=True), server_default=func.now(), nullable=False)

    stock = db.relationship('Stock', lazy='joined')
    user = db.relationship('User', lazy='joined')


class MarketSetting(TimestampMixin, db.Model):
    __tablename__ = "market_setting"
    id = db.Column(db.Integer, primary_key=True)
    hours = db.Column(db.String(50), nullable=False, default="08:00-17:00")
    schedule = db.Column(db.String(500), nullable=True, default="")
    open_days = db.Column(db.String(100), nullable=False,
                          default="Monday,Tuesday,Wednesday,Thursday,Friday")


class ClosureDates(TimestampMixin, db.Model):
    __tablename__ = "closure_dates"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    closure_date = db.Column(db.Date, nullable=False, unique=True)
    reason = db.Column(db.String(255), nullable=True)
    open_hour = db.Column(db.Integer, nullable=True)
    close_hour = db.Column(db.Integer, nullable=True)
    for_whole_day = db.Column(db.Boolean, nullable=False, default=True)


@app.template_filter("aztime")
def aztime(dt):
    if dt is None:
        return ""
    try:
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=AZ)
        else:
            dt = dt.astimezone(AZ)
        return dt.strftime("%Y-%m-%d %I:%M:%S %p")
    except Exception:
        return str(dt)


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

    now = datetime.now(AZ)
    weekday = now.strftime("%A")
    open_time, close_time = parse_market_hours(setting.hours or "")
    today = now.date()
    current_hour = now.hour
    current_time = now.time()

    open_days = (setting.open_days or "").split(",")
    market_open = (weekday in open_days) and (
        open_time <= current_time <= close_time)

# check closures (whole day and partial day)
    closed_today = ClosureDates.query.filter_by(closure_date=today).first()
    if closed_today:
        if closed_today.for_whole_day:
            market_open = False
        elif closed_today.open_hour is not None and closed_today.close_hour is not None:
            market_open = closed_today.open_hour <= current_hour < closed_today.close_hour
        else:
            market_open = False

    display_hours = f"{open_time.strftime('%H:%M')} to {close_time.strftime('%H:%M')}"

    closures = ClosureDates.query.order_by(
        ClosureDates.closure_date.asc()).all()

    formatted_closures = []  # list of dictionary of closures in the database
    for closure in closures:
        if closure.for_whole_day:
            desc = "Closed whole day"
        elif closure.open_hour is not None and closure.close_hour is not None:
            desc = f"{closure.open_hour:02d}:00 - {closure.close_hour:02d}:00"

        else:
            desc = "Partially closed (unspecified hours)"

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
    MU = 0.0003
    SIGMA = 0.0015
    JUMP_PROB = 0.004
    JUMP_SIZE = 0.01

    today_az = datetime.now(AZ).date()
    stocks = Stock.query.all()

    for stock in stocks:

        base = float(stock.current_price or 0) or 100.0
        pct = random.gauss(MU, SIGMA)
        if random.random() < JUMP_PROB:
            pct += random.uniform(-JUMP_SIZE, JUMP_SIZE)

        new_price = max(0.01, round(base * (1.0 + pct), 2))
        stock.current_price = new_price

        if stock.day_date != today_az or stock.day_open is None:
            stock.day_date = today_az
            stock.day_open = Decimal(str(new_price))
            stock.day_high = Decimal(str(new_price))
            stock.day_low = Decimal(str(new_price))
        else:
            npd = Decimal(str(new_price))
            if stock.day_high is None or npd > stock.day_high:
                stock.day_high = npd
            if stock.day_low is None or npd < stock.day_low:
                stock.day_low = npd

    db.session.commit()

    payload = {
        s.stock_ticker: {
            "price": float(s.current_price or 0),
            "day_high": float(s.day_high or 0),
            "day_low": float(s.day_low or 0),
        }
        for s in stocks
    }
    return jsonify(payload)


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
                 is_admin=is_admin)

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
    return ""


@app.route("/orders/add", methods=["POST"])
@login_required
def add_order():
    user_id = current_user.user_id
    stock_id = int(request.form.get("stock_id"))
    quantity = int(request.form.get("quantity", 0))

    stock = Stock.query.get_or_404(stock_id)

    form_price = request.form.get("price")
    fallback = Decimal(str(stock.current_price or 0))
    price = parse_price_or_fallback(form_price, fallback)
    if price <= 0 or quantity <= 0:
        flash("Invalid price or quantity.", "danger")
        return redirect(url_for("stocks"))

    if stock.available_stocks is not None and stock.available_stocks < quantity:
        flash("Not enough available shares.", "danger")
        return redirect(url_for("stocks"))

    acct = CashAccount.query.filter_by(user_id=user_id).first()
    if not acct:
        flash("No cash account found. Deposit first.", "danger")
        return redirect(url_for("wallet"))

    cost = (price * Decimal(quantity)).quantize(Decimal("0.01"))
    if Decimal(str(acct.current_balance)) < cost:
        flash("Insufficient funds.", "danger")
        return redirect(url_for("stocks"))

    acct.current_balance = (
        Decimal(str(acct.current_balance)) - cost
    ).quantize(Decimal("0.01"))

    if stock.available_stocks is not None:
        stock.available_stocks -= quantity

    pos = Portfolio.query.filter_by(user_id=user_id, stock_id=stock_id).first()
    if not pos:
        pos = Portfolio(
            user_id=user_id,
            stock_id=stock_id,
            quantity=0,
            purchase_price=Decimal("0.00"),
            current_price_snapshot=None,
        )
        db.session.add(pos)

    new_qty = pos.quantity + quantity
    if pos.quantity > 0:
        existing_cost = (Decimal(str(pos.purchase_price))
                         * Decimal(pos.quantity))
        total_cost = existing_cost + cost
        pos.purchase_price = (total_cost / Decimal(new_qty)
                              ).quantize(Decimal("0.01"))
    else:
        pos.purchase_price = price

    pos.quantity = new_qty
    pos.current_price_snapshot = price

    txn = Transaction(
        order_id=None,
        user_id=user_id,
        stock_id=stock_id,
        quantity=quantity,
        price=price,
        transaction_type=TransactionType.BUY
    )
    db.session.add(txn)

    db.session.commit()
    flash("Order executed.", "success")
    return redirect(url_for("portfolio", user_id=user_id))


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
    today = datetime.now(AZ).date()

    volumes = {}
    market_caps = {}
    outstanding_stocks = {}
    for stock in stocks:
        volume = db.session.query(func.sum(func.abs(Transaction.quantity))).filter(Transaction.stock_id == stock.id,
                                                                                   func.date(
                                                                                       Transaction.timestamp) == today
                                                                                   ).scalar()

        volumes[stock.id] = abs(volume or 0)

        total_held = db.session.query(func.sum(Portfolio.quantity)).filter(
            Portfolio.stock_id == stock.id).scalar() or 0

        outstanding_stocks[stock.id] = total_held
        if total_held > 0:
            current_price_decimal = Decimal(str(stock.current_price or 0))
            market_caps[stock.id] = float(
                (Decimal(total_held) * current_price_decimal).quantize(Decimal("0.01")))
        else:
            market_caps[stock.id] = 0.00

    return render_template('stocks.html',
                           stocks=stocks,
                           market=market,
                           volumes=volumes,
                           market_caps=market_caps,
                           outstanding_stocks=outstanding_stocks)


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


class CashAccount(TimestampMixin, db.Model):
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


class Portfolio(TimestampMixin, db.Model):
    __tablename__ = "portfolio"
    holding_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey(
        "user.user_id"), nullable=False)
    stock_id = db.Column(db.Integer, db.ForeignKey("stock.id"), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    purchase_price = db.Column(
        db.Numeric(14, 2), nullable=False, default=Decimal("0.00"))
    current_price_snapshot = db.Column(
        db.Numeric(14, 2), nullable=True, default=None)
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

    @event.listens_for(db.engine, "connect")
    def set_session_tz(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        try:
            try:
                cursor.execute("SET time_zone = 'America/Phoenix';")
            except Exception:
                cursor.execute("SET time_zone = '-07:00';")
        finally:
            cursor.close()


@app.route("/portfolio")
@login_required
def portfolio_index():

    return redirect(url_for("portfolio", user_id=current_user.user_id))


@app.route("/portfolio/<int:user_id>", methods=["GET"], endpoint="portfolio")
@login_required
def portfolio(user_id):
    user = User.query.get_or_404(user_id)
    acct = CashAccount.query.filter_by(user_id=user_id).first()
    positions = Portfolio.query.filter_by(user_id=user_id).all()
    market = get_market_context()

    updated_prices = False
    for pos in positions:
        latest_price = Decimal(str(pos.stock.current_price or 0))
        if latest_price > 0:
            latest_price = latest_price.quantize(Decimal("0.01"))
            if pos.current_price_snapshot is None or Decimal(str(pos.current_price_snapshot)) != latest_price:
                pos.current_price_snapshot = latest_price
                updated_prices = True
    if updated_prices:
        db.session.commit()

    txns = (Transaction.query
            .filter_by(user_id=user_id)
            .order_by(Transaction.timestamp.desc())
            .limit(50)
            .all())

    return render_template(
        "portfolio.html",
        user=user,
        acct=acct,
        positions=positions,
        market=market,
        txns=txns,
    )


@app.route('/add_cash/<int:user_id>/<float:amount>')
def add_cash(user_id, amount):
    try:
        amount_value = Decimal(str(amount)).quantize(Decimal("0.01"))
    except (InvalidOperation, ValueError):
        flash('Invalid amount.', 'error')
        return redirect(url_for('portfolio', user_id=user_id))

    if amount_value <= 0:
        flash('Amount must be greater than $0.00.', 'error')
        return redirect(url_for('portfolio', user_id=user_id))
    acct = CashAccount.query.filter_by(user_id=user_id).first()
    if not acct:
        acct = CashAccount(user_id=user_id, current_balance=amount_value)
        db.session.add(acct)
    else:
        acct.current_balance = (
            Decimal(str(acct.current_balance)) + amount_value
        ).quantize(Decimal("0.01"))

        txn = Transaction(
            order_id=None,
            user_id=user_id,
            stock_id=None,
            quantity=0,
            price=amount_value,
            transaction_type=TransactionType.DEPOSIT
        )
    db.session.add(txn)
    db.session.commit()
    flash(f'Added ${amount_value:.2f} to cash account.', 'success')
    return redirect(url_for('portfolio', user_id=user_id))


@app.route('/withdraw_cash/<int:user_id>/<float:amount>')
def withdraw_cash(user_id, amount):
    try:
        amount_value = Decimal(str(amount)).quantize(Decimal("0.01"))
    except (InvalidOperation, ValueError):
        flash('Invalid amount.', 'error')
        return redirect(url_for('portfolio', user_id=user_id))

    if amount_value <= 0:
        flash('Amount must be greater than $0.00.', 'error')
        return redirect(url_for('portfolio', user_id=user_id))
    acct = CashAccount.query.filter_by(user_id=user_id).first()
    if acct and Decimal(str(acct.current_balance)) >= amount_value:
        acct.current_balance = (
            Decimal(str(acct.current_balance)) - amount_value
        ).quantize(Decimal("0.01"))

        txn = Transaction(
            order_id=None,
            user_id=user_id,
            stock_id=None,
            quantity=0,
            price=amount_value,
            transaction_type=TransactionType.WITHDRAW
        )
        db.session.add(txn)
        db.session.commit()
        flash(f'Withdrew ${amount_value:.2f} from cash account.', 'success')
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

        price = Decimal(str(stock.current_price or 0))
        if price <= 0:
            flash("Invalid stock price.", "danger")
            return redirect(url_for('portfolio', user_id=user_id))

        total_cost = (price * Decimal(quantity)).quantize(Decimal("0.01"))

        acct = CashAccount.query.filter_by(user_id=user_id).first()
        if not acct:
            acct = CashAccount(
                user_id=user_id, current_balance=Decimal("0.00"))
            db.session.add(acct)
            db.session.flush()

        if Decimal(str(acct.current_balance)) < total_cost:
            flash("Insufficient funds.", "danger")
            return redirect(url_for('portfolio', user_id=user_id))

        acct.current_balance = (
            Decimal(str(acct.current_balance)) - total_cost).quantize(Decimal("0.01"))
        stock.available_stocks = stock.available_stocks - quantity

        t = Transaction(order_id=None, user_id=user_id,
                        stock_id=stock_id, quantity=quantity, price=price)  
        db.session.add(t)

        pos = Portfolio.query.filter_by(
            user_id=user_id, stock_id=stock_id).first()
        if pos:
            existing_qty = pos.quantity
            existing_cost = (Decimal(str(pos.purchase_price or 0))
                             * Decimal(existing_qty))
            new_cost = (price * Decimal(quantity))
            total_qty = existing_qty + quantity
            if total_qty > 0:
                pos.purchase_price = (
                    (existing_cost + new_cost) / Decimal(total_qty)
                ).quantize(Decimal("0.01"))
            pos.quantity = total_qty
            pos.current_price_snapshot = price.quantize(Decimal("0.01"))
        else:
            pos = Portfolio(user_id=user_id, stock_id=stock_id,
                            quantity=quantity,
                            purchase_price=price.quantize(Decimal("0.01")),
                            current_price_snapshot=price.quantize(Decimal("0.01")))
            db.session.add(pos)

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
    pos = Portfolio.query.get_or_404(holding_id)
    if pos.user_id != current_user.user_id:
        abort(403)

    sell_qty = int(request.form.get("quantity", 0))
    form_price = request.form.get("price")

    fallback = Decimal(str(pos.stock.current_price or 0))
    price = parse_price_or_fallback(form_price, fallback)
    if price <= 0 or sell_qty <= 0 or sell_qty > pos.quantity:
        flash("Invalid sell request.", "danger")
        return redirect(url_for("portfolio", user_id=current_user.user_id))

    proceeds = (price * Decimal(sell_qty)).quantize(Decimal("0.01"))

    stock = Stock.query.get(pos.stock_id)
    if stock is not None and stock.available_stocks is not None:
        stock.available_stocks += sell_qty

    pos.quantity -= sell_qty
    pos.current_price_snapshot = price
    if pos.quantity == 0:
        db.session.delete(pos)

    acct = CashAccount.query.filter_by(user_id=current_user.user_id).first()
    acct.current_balance = (
        Decimal(acct.current_balance) + proceeds).quantize(Decimal("0.01"))

    txn = Transaction(
        order_id=None,
        user_id=current_user.user_id,
        stock_id=pos.stock_id,
        quantity=-sell_qty,
        price=price,
        transaction_type=TransactionType.SELL
    )
    db.session.add(txn)

    db.session.commit()
    flash("Position sold.", "success")
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
        acct.current_balance += amount

    txn = Transaction(
        order_id=None,
        user_id=current_user.user_id,
        stock_id=None,
        quantity=0,
        price=amount,
        transaction_type=TransactionType.DEPOSIT
    )
    db.session.add(txn)
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

    acct.current_balance -= amount

    txn = Transaction(
        order_id=None,
        user_id=current_user.user_id,
        stock_id=None,
        quantity=0,
        price=amount,
        transaction_type=TransactionType.WITHDRAW
    )
    db.session.add(txn)
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

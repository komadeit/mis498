import os
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash 
import hashlib

app = Flask(__name__)
app.secret_key = "s3cr3t_key"

basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# KULLANICI TABLOSU
class User(db.Model):
    customer_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)  # Hashlenmiş şifre
    # Adres bilgileri artık ayrı bir tabloda tutuluyor.
    addresses = db.relationship("Address", backref="user", lazy=True)

# ADRESLER TABLOSU
class Address(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey('user.customer_id'), nullable=False)
    city = db.Column(db.String(50))
    district = db.Column(db.String(50))
    neighborhood = db.Column(db.String(50))
    address = db.Column(db.String(200))

class PaymentMethod(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey('user.customer_id'), nullable=False)
    card_number = db.Column(db.String(128), nullable=False)  
    last_four = db.Column(db.String(4), nullable=False)      
    expiry_date = db.Column(db.String(128), nullable=False) 
    expiry_date_display = db.Column(db.String(7), nullable=False)  
    cvv = db.Column(db.String(128), nullable=False)           

    def __repr__(self):
        return f"<PaymentMethod {self.id} - Customer: {self.customer_id}>"



def create_tables():
    db.create_all()

with app.app_context():
    create_tables()

# Mevcut dresses_data veriniz (ölçü bilgileri eklenmiş hal)
dresses_data = [
    {
        "id": "1",
        "name": "Kırmızı Tül Detaylı Abiye",
        "price": 299,
        "size": "M",
        "available": True,
        "imageUrl": "https://images.unsplash.com/photo-1595777457583-95e059d581b8?auto=format&fit=crop&q=80",
        "description": "Özel günler için tasarlanmış zarif bir abiye elbise.",
        "gogus": "90 cm",
        "bel": "70 cm",
        "kalca": "95 cm"
    },
    {
        "id": "2",
        "name": "Mavi Yazlık Elbise",
        "price": 349,
        "size": "S",
        "available": True,
        "imageUrl": "https://images.unsplash.com/photo-1539008835657-9e8e9680c956?auto=format&fit=crop&q=80",
        "description": "Yırtmaç detaylı bebek mavisi yazlık elbise.",
        "gogus": "88 cm",
        "bel": "68 cm",
        "kalca": "92 cm"
    },
    {
        "id": "3",
        "name": "Mavi İpek Gece Elbisesi",
        "price": 399,
        "size": "L",
        "available": False,
        "imageUrl": "https://images.unsplash.com/photo-1566174053879-31528523f8ae?auto=format&fit=crop&q=80",
        "description": "Zarif ipek kumaştan üretilmiş gece elbisesi.",
        "gogus": "92 cm",
        "bel": "72 cm",
        "kalca": "98 cm"
    },
    {
        "id": "4",
        "name": "Siyah Gece Elbisesi",
        "price": 499,
        "size": "S",
        "available": True,
        "imageUrl": "https://images.unsplash.com/photo-1589212987511-4a924cb9d8ac?q=80&w=1964&auto=format&fit=crop&ixlib=rb-4.0.3&ixid=M3wxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8fA==",
        "description": "Siyah gece elbisesi. Sade şıklık tercih edenler için.",
        "gogus": "86 cm",
        "bel": "66 cm",
        "kalca": "90 cm"
    },
    {
        "id": "5",
        "name": "Yeşil Kadife Elbise",
        "price": 279,
        "size": "M",
        "available": True,
        "imageUrl": "https://images.unsplash.com/photo-1550639525-c97d455acf70?auto=format&fit=crop&q=80",
        "description": "Kadife dokulu şık tasarım.",
        "gogus": "89 cm",
        "bel": "69 cm",
        "kalca": "94 cm"
    },
    {
        "id": "6",
        "name": "Kırmızı Tül Prenses Elbise",
        "price": 459,
        "size": "L",
        "available": True,
        "imageUrl": "https://images.unsplash.com/photo-1568252542512-9fe8fe9c87bb?q=80&w=2038&auto=format&fit=crop&ixlib=rb-4.0.3&ixid=M3wxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8fA==",
        "description": "Romantik tül detaylı tasarım.",
        "gogus": "93 cm",
        "bel": "73 cm",
        "kalca": "99 cm"
    },
    {
        "id": "7",
        "name": "Beyaz Dantel Gelinlik",
        "price": 899,
        "size": "M",
        "available": True,
        "imageUrl": "https://images.unsplash.com/photo-1594552072238-b8a33785b261?auto=format&fit=crop&q=80",
        "description": "Zarif dantel işlemeli gelinlik.",
        "gogus": "95 cm",
        "bel": "75 cm",
        "kalca": "100 cm"
    },
    {
        "id": "8",
        "name": "Mor Şifon Abiye",
        "price": 329,
        "size": "S",
        "available": True,
        "imageUrl": "https://images.unsplash.com/photo-1591369822096-ffd140ec948f?auto=format&fit=crop&q=80",
        "description": "Uçuşan şifon detaylı tasarım.",
        "gogus": "87 cm",
        "bel": "67 cm",
        "kalca": "91 cm"
    },
    {
        "id": "9",
        "name": "Gümüş Simli Gece Elbisesi",
        "price": 549,
        "size": "L",
        "available": False,
        "imageUrl": "https://images.unsplash.com/photo-1595777457583-95e059d581b8?auto=format&fit=crop&q=80",
        "description": "Işıltılı gece elbisesi.",
        "gogus": "91 cm",
        "bel": "71 cm",
        "kalca": "97 cm"
    },
    {
        "id": "10",
        "name": "Tül Dantel Gelinlik",
        "price": 429,
        "size": "M",
        "available": True,
        "imageUrl": "https://images.unsplash.com/photo-1593575620619-602b4ddf6e96?q=80&w=1974&auto=format&fit=crop&ixlib=rb-4.0.3&ixid=M3wxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8fA==",
        "description": "Zarif tasarım tül dantel detaylı gelinlik.",
        "gogus": "94 cm",
        "bel": "74 cm",
        "kalca": "101 cm"
    }
]

@app.route("/profile/payment-methods", methods=["GET", "POST"])
def payment_methods_route():
    if "user" not in session:
        return redirect(url_for("login_route"))
    
    user = User.query.filter_by(email=session["user"]).first()
    if not user:
        flash("Kullanıcı bulunamadı!")
        return redirect(url_for("login_route"))
    
    if request.method == "POST":
        # Gizli inputlardan alınan temiz veriler:
        card_number_raw = request.form.get("card_number", "").strip()      # Örneğin: "1234567890123456"
        expiry_date_raw = request.form.get("expiry_date", "").strip()      # Örneğin: "122025"
        expiry_date_display = request.form.get("expiry_date_display", "").strip()  # "MM/YYYY"
        cvv_raw = request.form.get("cvv", "").strip()
        
        # Validasyon
        if not (card_number_raw.isdigit() and len(card_number_raw) == 16):
            flash("Kart numarası 16 basamaklı rakam olmalıdır!")
            return redirect(url_for("payment_methods_route"))
        if not (expiry_date_raw.isdigit() and len(expiry_date_raw) == 6 and 1 <= int(expiry_date_raw[:2]) <= 12):
            flash("Son kullanma tarihi MMYYYY formatında olmalıdır!")
            return redirect(url_for("payment_methods_route"))
        if not (cvv_raw.isdigit() and len(cvv_raw) == 3):
            flash("CVV 3 basamaklı rakam olmalıdır!")
            return redirect(url_for("payment_methods_route"))
        
        last_four = card_number_raw[-4:]
        card_number_hashed = hashlib.sha256(card_number_raw.encode()).hexdigest()
        expiry_date_hashed = hashlib.sha256(expiry_date_raw.encode()).hexdigest()
        cvv_hashed = hashlib.sha256(cvv_raw.encode()).hexdigest()
        
        new_payment = PaymentMethod(
            customer_id=user.customer_id,
            card_number=card_number_hashed,
            last_four=last_four,
            expiry_date=expiry_date_hashed,
            expiry_date_display=expiry_date_display,
            cvv=cvv_hashed
        )
        db.session.add(new_payment)
        db.session.commit()
        flash("Ödeme yöntemi eklendi!")
        return redirect(url_for("payment_methods_route"))
    
    payment_methods = PaymentMethod.query.filter_by(customer_id=user.customer_id).all()
    return render_template("payment_methods.html", payment_methods=payment_methods)

@app.route("/profile/payment-methods/delete/<int:pm_id>", methods=["POST"])
def delete_payment_method(pm_id):
    # Kullanıcı oturum kontrolü
    if "user" not in session:
        flash("Önce giriş yapın!")
        return redirect(url_for("login_route"))
    
    user = User.query.filter_by(email=session["user"]).first()
    if not user:
        flash("Kullanıcı bulunamadı!")
        return redirect(url_for("login_route"))
    
    # Kullanıcının tüm ödeme yöntemlerini çekelim
    payment_methods = PaymentMethod.query.filter_by(customer_id=user.customer_id).all()
    
    # Eğer sadece 1 ödeme yöntemi varsa silme işlemi yapılamaz
    if len(payment_methods) <= 1:
        flash("En az bir ödeme yöntemi olması gerektiğinden ödeme yöntemi silinemiyor!")
        return redirect(url_for("payment_methods_route"))
    
    # Silinmek istenen ödeme yöntemini, kullanıcının ödeme yöntemleri arasında arayalım
    pm = PaymentMethod.query.filter_by(id=pm_id, customer_id=user.customer_id).first()
    if not pm:
        flash("Ödeme yöntemi bulunamadı!")
        return redirect(url_for("payment_methods_route"))
    
    db.session.delete(pm)
    db.session.commit()
    flash("Ödeme yöntemi silindi!")
    return redirect(url_for("payment_methods_route"))

@app.route("/profile/addresses", methods=["GET", "POST"])
def profile_addresses():
    if "user" not in session:
        return redirect(url_for("login_route"))
    
    user = User.query.filter_by(email=session["user"]).first()
    if not user:
        flash("Kullanıcı bulunamadı!")
        return redirect(url_for("login_route"))
    
    if request.method == "POST":
        # Yeni adres ekleme
        city = request.form.get("city")
        district = request.form.get("district")
        neighborhood = request.form.get("neighborhood")
        addr_text = request.form.get("address")
        
        existing_addresses = Address.query.filter_by(customer_id=user.customer_id).all()
        if len(existing_addresses) >= 5:
            flash("Maksimum 5 adres ekleyebilirsiniz!")
            return redirect(url_for("profile_addresses"))
        
        new_addr = Address(
            customer_id=user.customer_id,
            city=city,
            district=district,
            neighborhood=neighborhood,
            address=addr_text
        )
        try:
            db.session.add(new_addr)
            db.session.commit()
            flash("Adres başarıyla eklendi!")
        except Exception:
            db.session.rollback()
            flash("Adres eklenemedi!")
        return redirect(url_for("profile_addresses"))
    
    # GET ise adresleri listele
    addresses = Address.query.filter_by(customer_id=user.customer_id).all()
    return render_template("profile_addresses.html", addresses=addresses)

@app.route("/profile/addresses/delete/<int:addr_id>", methods=["POST"])
def delete_address(addr_id):
    if "user" not in session:
        return redirect(url_for("login_route"))
    user = User.query.filter_by(email=session["user"]).first()
    if not user:
        flash("Kullanıcı bulunamadı!")
        return redirect(url_for("login_route"))
    
    addresses = Address.query.filter_by(customer_id=user.customer_id).all()
    if len(addresses) <= 1:
        flash("En az 1 adres olmak zorunda!")
        return redirect(url_for("profile_addresses"))
    
    addr = Address.query.get(addr_id)
    if addr and addr.customer_id == user.customer_id:
        try:
            db.session.delete(addr)
            db.session.commit()
            flash("Adres silindi!")
        except Exception:
            db.session.rollback()
            flash("Adres silinemedi!")
    else:
        flash("Adres bulunamadı!")
    return redirect(url_for("profile_addresses"))

@app.route("/profile/change-password", methods=["GET", "POST"])
def change_password():
    if "user" not in session:
        return redirect(url_for("login_route"))
    
    user = User.query.filter_by(email=session["user"]).first()
    if not user:
        flash("Kullanıcı bulunamadı!", "error")
        return redirect(url_for("login_route"))
    
    if request.method == "POST":
        old_password = request.form.get("old_password")
        new_password = request.form.get("new_password")
        confirm_new_password = request.form.get("confirm_new_password")
        
        if not check_password_hash(user.password, old_password):
            flash("Eski şifrenizi yanlış girdiniz!", "error")
            return render_template("change_password.html")
        
        if check_password_hash(user.password, new_password):
            flash("Yeni şifreniz eskisiyle aynı olamaz!", "error")
            return render_template("change_password.html")
        
        if new_password != confirm_new_password:
            flash("Yeni şifreler uyuşmuyor!", "error")
            return render_template("change_password.html")
        
        try:
            user.password = generate_password_hash(new_password)
            db.session.commit()
            flash("Şifre başarıyla değiştirildi!", "success")
            return render_template("change_password.html")  # Redirect yerine render
        except Exception as e:
            db.session.rollback()
            flash("Şifre değiştirilemedi, lütfen tekrar deneyin!", "error")
            return render_template("change_password.html")
    
    return render_template("change_password.html")

@app.route("/nasil_calisir")
def nasil_calisir():
    return render_template("nasil_calisir.html")

@app.route("/dresses")
def dresses():
    return render_template("dresses.html", dresses=dresses_data)

@app.route("/signup", methods=["GET", "POST"])
def signup_route():
    if "user" in session:
        return redirect(url_for("index"))
    
    if request.method == "POST":
        name = request.form.get("name")
        email = request.form.get("email")
        password = request.form.get("password")
        confirmPassword = request.form.get("confirmPassword")
        city = request.form.get("city")
        district = request.form.get("district")
        neighborhood = request.form.get("neighborhood")
        addr_text = request.form.get("address")
        
        if password != confirmPassword:
            flash("Şifreler uyuşmuyor!")
            return redirect(url_for("signup_route"))
        
        if User.query.filter_by(email=email).first():
            flash("Bu e-posta zaten kayıtlı!")
            return redirect(url_for("signup_route"))
        
        hashed_password = generate_password_hash(password)
        new_user = User(
            name=name,
            email=email,
            password=hashed_password
        )
        db.session.add(new_user)
        db.session.commit()
        
        if city or district or neighborhood or addr_text:
            new_address = Address(
                customer_id=new_user.customer_id,
                city=city,
                district=district,
                neighborhood=neighborhood,
                address=addr_text
            )
            db.session.add(new_address)
            db.session.commit()
        
        flash("Kayıt Başarılı")
        return redirect(url_for("signup_route"))
    
    return render_template("signup.html")


@app.route("/login", methods=["GET", "POST"])
def login_route():
    if request.method == "GET":
        if "user" in session:
            return redirect(url_for("index"))
        return render_template("login.html")
    
    email = request.form.get("email")
    password = request.form.get("password")
    user = User.query.filter_by(email=email).first()
    if user and check_password_hash(user.password, password):
        session["user"] = email
        flash("Giriş başarılı!")
        return render_template("login.html")
    else:
        flash("Hatalı e-posta veya şifre!")
        return render_template("login.html")



@app.route("/profile")
def profile():
    if "user" not in session:
        return redirect(url_for("login_route"))
    return render_template("profile.html")

@app.route("/contact")
def contact():
    return render_template("contact.html")

@app.route("/dress/<id>")
def dress_detail(id):
    dress = next((d for d in dresses_data if d["id"] == id), None)
    if not dress:
        return "Elbise bulunamadı", 404
    logged_in = "user" in session
    return render_template("dress_detail.html", dress=dress, logged_in=logged_in)

@app.route("/")
def index():
    first_four = dresses_data[:4]
    return render_template("index.html", dresses=first_four)

@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("index"))

@app.errorhandler(404)
def page_not_found(error):
    return render_template("404.html"), 404

if __name__ == "__main__":
    app.run(debug=True)

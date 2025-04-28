import os
from flask import Flask, render_template, request, redirect, url_for, flash, session, abort, current_app
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash 
from werkzeug.utils import secure_filename
import hashlib
from PIL import Image
from uuid import uuid4
import unicodedata
import base64
import re
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = "s3cr3t_key"

ADMIN_EMAIL = "admin@vestie.com"
ADMIN_PASSWORD_HASH = generate_password_hash("admin")

basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

def standardize_email(raw_email: str) -> str:
    email = raw_email.strip()
    email = unicodedata.normalize('NFKC', email)
    email = email.lower()
    return email

@app.template_filter('date')
def format_date(value, format='%d %B %Y'):

    if isinstance(value, datetime):
        return value.strftime(format)
    return value

def slugify(text):
    text = unicodedata.normalize('NFKD', text)
    text = text.encode('ascii', 'ignore').decode('ascii')
    text = re.sub(r'[^a-zA-Z0-9\s-]', '', text).strip().lower()
    return re.sub(r'\s+', '-', text)

app.jinja_env.globals['slugify'] = slugify

# KULLANICI TABLOSU
class User(db.Model):
    customer_id = db.Column(db.Integer, primary_key=True)
    firstname = db.Column(db.String(100), nullable=False)
    lastname = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    addresses = db.relationship("Address", backref="user", lazy=True)
    user_dresses = db.relationship("UserDress", backref="user", lazy=True)
    profile_pic_url = db.Column(db.String(500), nullable=True, default="/static/images/default_profile.jpg")
    payment_methods = db.relationship("PaymentMethod", backref="user", lazy=True)

# ADRESLER TABLOSU
class Address(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey('user.customer_id'), nullable=False)
    city = db.Column(db.String(50))
    district = db.Column(db.String(50))
    neighborhood = db.Column(db.String(50))
    address = db.Column(db.String(200))

# ÖDEME YÖNTEMLERİ TABLOSU
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

# YÜKLENEN ELBİSELER TABLOSU
class UserDress(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.customer_id'), nullable=False)
    name = db.Column(db.String(200), nullable=False)
    price = db.Column(db.Integer, nullable=False)
    available = db.Column(db.Boolean, default=True)
    description = db.Column(db.String(500))
    standard_size = db.Column(db.String(10), nullable=True)
    chest = db.Column(db.String(20), nullable=True)
    waist = db.Column(db.String(20), nullable=True)
    hip = db.Column(db.String(20), nullable=True)
    dress_pictures = db.relationship("DressPicture", backref="dress", lazy=True)

    @property
    def cover_url(self):
        cover = next((pic for pic in self.dress_pictures if pic.is_cover), None)
        if not cover:
            cover = self.dress_pictures[0]
        return cover.picture_url

# FOTOĞRAF KAYITLARI TABLOSU 
class DressPicture(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    dress_id = db.Column(db.Integer, db.ForeignKey('user_dress.id'), nullable=False)
    customer_id = db.Column(db.Integer, db.ForeignKey('user.customer_id'), nullable=False)
    picture_url = db.Column(db.String(500), nullable=False)
    is_cover = db.Column(db.Boolean, default=False)

# ADMİN PANELİNDE GÖRÜNTÜLEME İÇİN LOGİN LOG TABLOSU
class LoginLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.customer_id'), nullable=True)
    is_admin = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship("User", backref="login_logs")

def create_tables():
    db.create_all()

with app.app_context():
    create_tables()

@app.route("/profile/ilanlar", methods=["GET", "POST"])
def my_listings():
    if "user" not in session:
        return redirect(url_for("login_route"))
    user = User.query.filter_by(email=session["user"]).first()
    if not user:
        flash("Kullanıcı bulunamadı!")
        return redirect(url_for("login_route"))

    if request.method == "POST":
        dress_id = request.form.get("dress_id", type=int)
        action   = request.form.get("action")
        dress = UserDress.query.get(dress_id)
        if not dress or dress.user_id != user.customer_id:
            flash("Yetkisiz işlem!")
            return redirect(url_for("my_listings"))

        if action == "update":
            new_price = request.form.get("price", type=int)
            dress.price     = new_price if new_price is not None else dress.price
            dress.available = True if request.form.get("available") == "true" else False
            db.session.commit()
            flash("İlan güncellendi!")
        elif action == "delete":
            db.session.delete(dress)
            db.session.commit()
            flash("İlan silindi!")

        return redirect(url_for("my_listings"))

    dresses = user.user_dresses  
    return render_template("ilanlar.html", dresses=dresses)

@app.route("/user/<username>")
def public_profile(username):
    user = None
    for u in User.query.all():
        if slugify(f"{u.firstname} {u.lastname}") == username:
            user = u
            break
    if not user:
        abort(404)

    primary_addr = user.addresses[0] if user.addresses else None
    city = primary_addr.city if primary_addr else ""

    dresses = []
    for d in user.user_dresses:
        size = d.standard_size or f"{d.chest} / {d.waist} / {d.hip}"
        dresses.append({
            "id": d.id,
            "name": d.name,
            "price": d.price,
            "size": size,
            "available": d.available,
            "imageUrl": d.cover_url,
        })

    rating = 0
    review_count = 0

    return render_template("public_profile.html",
                           user=user,
                           city=city,
                           rating=rating,
                           review_count=review_count,
                           dresses=dresses)

@app.route("/profile/payment-methods", methods=["GET", "POST"])
def payment_methods_route():
    if "user" not in session:
        return redirect(url_for("login_route"))
    
    user = User.query.filter_by(email=session["user"]).first()
    if not user:
        flash("Kullanıcı bulunamadı!")
        return redirect(url_for("login_route"))
    
    if request.method == "POST":
        card_number_raw = request.form.get("card_number", "").strip()      
        expiry_date_raw = request.form.get("expiry_date", "").strip()      
        expiry_date_display = request.form.get("expiry_date_display", "").strip()  
        cvv_raw = request.form.get("cvv", "").strip()
        
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
    if "user" not in session:
        flash("Önce giriş yapın!")
        return redirect(url_for("login_route"))
    
    user = User.query.filter_by(email=session["user"]).first()
    if not user:
        flash("Kullanıcı bulunamadı!")
        return redirect(url_for("login_route"))
    
    payment_methods = PaymentMethod.query.filter_by(customer_id=user.customer_id).all()
    
    if len(payment_methods) <= 1:
        flash("En az bir ödeme yöntemi olması gerektiğinden ödeme yöntemi silinemiyor!")
        return redirect(url_for("payment_methods_route"))
    
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
            return render_template("change_password.html")
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
    db_dresses = UserDress.query.all()
    dresses_list = []
    for d in db_dresses:
        size = d.standard_size or f"{d.chest} / {d.waist} / {d.hip}"
        dresses_list.append({
            "id": d.id,
            "name": d.name,
            "price": d.price,
            "size": size,
            "available": d.available,
            "imageUrl": d.cover_url,
            "description": d.description
        })
    return render_template("dresses.html", dresses=dresses_list)

@app.route("/signup", methods=["GET", "POST"])
def signup_route():
    if "user" in session:
        return redirect(url_for("index"))
    
    if request.method == "POST":
        firstname = request.form.get("firstname")
        lastname = request.form.get("lastname")
        raw_email = request.form.get("email", "")
        email = standardize_email(raw_email)
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
            firstname=firstname,
            lastname=lastname,
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
        if session.get("admin"):
            return redirect(url_for("admin_dashboard"))
        if session.get("user"):
            return redirect(url_for("index"))
        return render_template("login.html")
    
    raw_email = request.form.get("email", "")
    email = standardize_email(raw_email)
    password = request.form.get("password", "")

    if email == ADMIN_EMAIL and check_password_hash(ADMIN_PASSWORD_HASH, password):
        session.clear()
        session["admin"] = True
        db.session.add(LoginLog(user_id=None, is_admin=True))
        db.session.commit()
        flash("Admin olarak giriş yaptınız!", "success")
        return redirect(url_for("admin_dashboard"))

    user = User.query.filter_by(email=email).first()
    if user and check_password_hash(user.password, password):
        session.clear()
        session["user"] = email
        db.session.add(LoginLog(user_id=user.customer_id, is_admin=False))
        db.session.commit()
        flash("Giriş başarılı!", "success")
        return render_template("login.html")

    flash("Hatalı e-posta veya şifre!", "error")
    return render_template("login.html")

@app.route("/upload-dress", methods=["GET", "POST"])
def upload_dress():
    if "user" not in session:
        flash("Önce giriş yapın!")
        return redirect(url_for("login_route"))
    user = User.query.filter_by(email=session["user"]).first()
    if not user:
        flash("Kullanıcı bulunamadı!")
        return redirect(url_for("login_route"))
    
    if request.method == "POST":
        name = request.form.get("name")
        price = request.form.get("price")
        size_type = request.form.get("size_type") 
        standard_size = None
        chest = None
        waist = None
        hip = None
        if size_type == "standard":
            standard_size = request.form.get("standard_size")
        elif size_type == "custom":
            chest = request.form.get("chest")
            waist = request.form.get("waist")
            hip = request.form.get("hip")
        available = True  
        description = request.form.get("description")
        cover_index = request.form.get("cover_index", "0")
        try:
            cover_index = int(cover_index)
        except:
            cover_index = 0
        
        photos = request.files.getlist("photo")
        uploaded_files = [file for file in photos if file.filename != ""]
        if len(uploaded_files) == 0:
            flash("Lütfen en az bir fotoğraf yükleyin!")
            return redirect(url_for("upload_dress"))
        
        new_dress = UserDress(
            user_id=user.customer_id,
            name=name,
            price=int(price) if price and price.isdigit() else 0,
            available=available,
            description=description,
            standard_size=standard_size,
            chest=chest,
            waist=waist,
            hip=hip
        )
        db.session.add(new_dress)
        db.session.commit()  
        
        upload_folder = os.path.join(app.root_path, "static/uploads/dresspics")
        if not os.path.exists(upload_folder):
            os.makedirs(upload_folder)
        
        for idx, file in enumerate(uploaded_files):
            temp_filename = secure_filename(file.filename)
            temp_path = os.path.join(upload_folder, "temp_" + temp_filename)
            file.save(temp_path)
            new_filename = f"{user.customer_id}_{new_dress.id}_{uuid4().hex}.jpg"
            new_file_path = os.path.join(upload_folder, new_filename)
            
            try:
                with Image.open(temp_path) as img:
                    if img.mode in ("RGBA", "P"):
                        img = img.convert("RGB")
                    img.save(new_file_path, "JPEG")
            except Exception as e:
                flash("Fotoğraf işlenirken hata oluştu!")
                os.remove(temp_path)
                continue
            
            os.remove(temp_path)
            photo_url = url_for("static", filename="uploads/dresspics/" + new_filename)
            
            new_picture = DressPicture(
                dress_id=new_dress.id,
                customer_id=user.customer_id,
                picture_url=photo_url,
                is_cover=(idx == cover_index)
            )
            db.session.add(new_picture)
        
        db.session.commit()
        flash("Elbise başarıyla yüklendi!")
        return redirect(url_for("upload_dress"))
    
    return render_template("upload_dress.html")

@app.route("/profile")
def profile():
    if "user" not in session:
        return redirect(url_for("login_route"))
    user = User.query.filter_by(email=session["user"]).first()
    if not user:
        flash("Kullanıcı bulunamadı!")
        return redirect(url_for("login_route"))
    return render_template("profile.html", user=user)

@app.route("/profile/update", methods=["GET", "POST"])
def update_profile():
    if "user" not in session:
        return redirect(url_for("login_route"))
    user = User.query.filter_by(email=session["user"]).first()
    if not user:
        flash("Kullanıcı bulunamadı!")
        return redirect(url_for("login_route"))

    if request.method == "POST":
        old_firstname = user.firstname
        old_lastname = user.lastname
        old_email = user.email

        new_firstname = request.form.get("firstname")
        new_lastname = request.form.get("lastname")
        new_email = request.form.get("email")

        info_changed = (old_firstname != new_firstname or old_lastname != new_lastname or old_email != new_email)

        picture_changed = False

        remove_pic = request.form.get("remove_profile_pic")
        default_pic = "/static/images/default_profile.jpg"
        if remove_pic == "on":
            if user.profile_pic_url and user.profile_pic_url != default_pic:
                file_path = os.path.join(app.root_path, user.profile_pic_url.lstrip("/"))
                if os.path.exists(file_path):
                    try:
                        os.remove(file_path)
                    except Exception as remove_error:
                        app.logger.error(f"Profil fotoğrafı silinemedi: {remove_error}")
            user.profile_pic_url = default_pic
            picture_changed = True

        cropped_data = request.form.get("cropped_image")
        if cropped_data:
            pattern = r"data:image/(.*?);base64,(.*)"
            match = re.match(pattern, cropped_data)
            if match:
                ext = match.group(1)  
                encoded_data = match.group(2)
                image_data = base64.b64decode(encoded_data)
                upload_folder = os.path.join(app.root_path, "static/uploads/profilepictures")
                if not os.path.exists(upload_folder):
                    os.makedirs(upload_folder)
                new_filename = f"{user.customer_id}_{uuid4().hex}.{ext}"
                file_path = os.path.join(upload_folder, new_filename)
                with open(file_path, "wb") as f:
                    f.write(image_data)
                user.profile_pic_url = url_for("static", filename="uploads/profilepictures/" + new_filename)
                picture_changed = True

        elif "profile_pic" in request.files:
            file = request.files.get("profile_pic")
            if file and file.filename != "":
                upload_folder = os.path.join(app.root_path, "static/uploads/profilepictures")
                if not os.path.exists(upload_folder):
                    os.makedirs(upload_folder)
                ext = os.path.splitext(secure_filename(file.filename))[1].lower()
                new_filename = f"{user.customer_id}_{uuid4().hex}{ext}"
                file_path = os.path.join(upload_folder, new_filename)
                file.save(file_path)
                user.profile_pic_url = url_for("static", filename="uploads/profilepictures/" + new_filename)
                picture_changed = True

        existing = User.query.filter(User.email == new_email, User.customer_id != user.customer_id).first()
        if existing:
            flash("Bu e-posta zaten kullanılıyor!")
            return redirect(url_for("update_profile"))

        user.firstname = new_firstname
        user.lastname = new_lastname
        user.email = new_email

        try:
            db.session.commit()
            messages = []
            if picture_changed:
                if remove_pic == "on":
                    messages.append("Profil fotoğrafınız kaldırıldı!")
                else:
                    messages.append("Profil fotoğrafınız güncellendi!")
            if info_changed:
                messages.append("Profil bilgileriniz güncellendi!")
            flash(" ".join(messages))
            session["user"] = new_email
            return render_template("update_profile.html", user=user, redirect_after=3000)
        except Exception as e:
            db.session.rollback()
            flash("Profil bilgileriniz güncellenemedi!")
            return redirect(url_for("update_profile"))

    return render_template("update_profile.html", user=user)


@app.route("/contact")
def contact():
    return render_template("contact.html")

@app.route("/dress/<int:id>")
def dress_detail(id):
    d = UserDress.query.get_or_404(id)

    dress = {
        "id":             d.id,
        "name":           d.name,
        "price":          d.price,
        "available":      d.available,
        "description":    d.description,
        "gogus":          d.chest or "",
        "bel":            d.waist or "",
        "kalca":          d.hip or "",
        "size":           d.standard_size or "",
        "pictures":       [pic.picture_url for pic in d.dress_pictures],
        "imageUrl":       d.cover_url,
        "uploader_id":    d.user.customer_id,
        "uploader_name":  f"{d.user.firstname} {d.user.lastname}",
        "uploader_pic":   d.user.profile_pic_url,
        "uploader_slug":  slugify(f"{d.user.firstname} {d.user.lastname}"),
    }

    # Giriş durumunu ve admin durumunu flag olarak ekleyelim
    logged_in = bool(session.get("user"))
    is_admin  = bool(session.get("admin"))

    return render_template(
        "dress_detail.html",
        dress=dress,
        logged_in=logged_in,
        is_admin=is_admin
    )

@app.route("/")
def index():
    # En yeni 5 elbise
    latest = UserDress.query.order_by(UserDress.id.desc()).limit(5).all()
    dresses = []
    for d in latest:
        size = d.standard_size or f"{d.chest} / {d.waist} / {d.hip}"
        dresses.append({
            "id": d.id,
            "name": d.name,
            "price": d.price,
            "size": size,
            "available": d.available,
            "imageUrl": d.cover_url
        })
    return render_template("index.html", dresses=dresses)

@app.route("/logout")
def logout():
    session.pop("user", None)
    session.clear()
    return redirect(url_for("index"))

@app.route("/admin")
def admin_dashboard():
    # Sadece admin oturumu varsa devam etsin
    if not session.get("admin"):
        abort(403)

    # Panodaki metrikler
    total_users       = User.query.count()
    total_listings    = UserDress.query.count()
    total_logins      = LoginLog.query.count()
    # Son 24 saatteki benzersiz kullanıcı girişleri
    since = datetime.utcnow() - timedelta(days=1)
    unique_recent_users = (
        LoginLog
        .query
        .filter(LoginLog.timestamp >= since, LoginLog.is_admin == False)
        .with_entities(LoginLog.user_id)
        .distinct()
        .count()
    )

    return render_template(
        "admin.html",
        total_users=total_users,
        total_listings=total_listings,
        total_logins=total_logins,
        unique_recent_users=unique_recent_users
    )

@app.route("/admin/users", methods=["GET", "POST"])
def admin_users():
    if not session.get("admin"):
        abort(403)

    if request.method == "POST":
        uid = request.form.get("user_id")
        user = User.query.get(uid)
        if user:
            # 1) İlan resimlerini sil
            for dress in user.user_dresses:
                for pic in dress.dress_pictures:
                    db.session.delete(pic)
                db.session.delete(dress)
            # 2) Ödeme yöntemlerini sil
            for pm in user.payment_methods:
                db.session.delete(pm)
            # 3) Adresleri sil
            for addr in user.addresses:
                db.session.delete(addr)
            # 4) Son olarak kullanıcıyı sil
            db.session.delete(user)
            db.session.commit()
            flash(f"{user.firstname} {user.lastname} başarıyla silindi.", "success")
        return redirect(url_for("admin_users"))

    users = User.query.all()
    return render_template("adminusers.html", users=users)


@app.route("/admin/ilanlar", methods=["GET", "POST"])
def admin_listings():
    if not session.get("admin"):
        abort(403)

    # Silme işlemi
    if request.method == "POST":
        dress_id = request.form.get("dress_id")
        dress = UserDress.query.get(dress_id)
        if dress:
            # 1) Fiziksel fotoğraf dosyalarını sil
            for pic in dress.dress_pictures:
                try:
                    # picture_url örn "/static/uploads/dresspics/xyz.jpg"
                    filepath = os.path.join(current_app.root_path, pic.picture_url.lstrip("/"))
                    if os.path.exists(filepath):
                        os.remove(filepath)
                except Exception:
                    pass
                db.session.delete(pic)

            # 2) İlanı sil
            db.session.delete(dress)
            db.session.commit()
            flash(f"İlan #{dress_id} silindi.", "success")
        return redirect(url_for("admin_listings"))

    # GET: sadece müsait (=available=True) ilanları çek
    listings = UserDress.query.filter_by(available=True).all()
    return render_template("adminilanlar.html", listings=listings)

@app.route("/admin/ilanlar/delete/<int:id>", methods=["POST"])
def admin_delete_listing(id):
    if not session.get("admin"):
        abort(403)
    dress = UserDress.query.get_or_404(id)

    # 1) Fiziksel dosyaları sil
    for pic in dress.dress_pictures:
        try:
            path = os.path.join(current_app.root_path, pic.picture_url.lstrip("/"))
            if os.path.exists(path):
                os.remove(path)
        except:
            pass
        db.session.delete(pic)

    # 2) İlanı sil
    db.session.delete(dress)
    db.session.commit()
    flash(f"İlan #{id} silindi.", "success")
    return redirect(url_for("admin_listings"))

@app.errorhandler(404)
def page_not_found(error):
    return render_template("404.html"), 404

if __name__ == "__main__":
    app.run(debug=True)

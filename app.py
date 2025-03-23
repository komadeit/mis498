from flask import Flask, render_template, request, redirect, url_for, flash, session

app = Flask(__name__)
app.secret_key = "s3cr3t_key"

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

@app.route("/nasil_calisir")
def nasil_calisir():
    return render_template("nasil_calisir.html")

@app.route("/dresses")
def dresses():
    # Tüm 10 elbise verisini gönderiyoruz
    return render_template("dresses.html", dresses=dresses_data)

@app.route("/signup")
def signup():
    return render_template("signup.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        if email == "test@gmail.com" and password == "admin":
            session["user"] = email
            return redirect(url_for("index"))
        else:
            flash("Hatalı e-posta veya şifre!")
            return render_template("login.html")
    return render_template("login.html")

@app.route("/profile")
def profile():
    if "user" not in session:
        return redirect(url_for("login"))
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

if __name__ == "__main__":
    app.run(debug=True)

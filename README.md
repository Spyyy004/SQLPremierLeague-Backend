## **🚀 Steps to Setup the Backend Locally**

### **1️⃣ Install PostgreSQL**
You need **PostgreSQL** installed on your system. Follow the instructions for your OS:

#### **📌 MacOS (Homebrew)**
```sh
brew install postgresql
brew services start postgresql
```

#### **📌 Ubuntu/Linux**
```sh
sudo apt update
sudo apt install postgresql postgresql-contrib
sudo systemctl start postgresql
```

#### **📌 Windows (via WSL)**
```sh
sudo apt install postgresql postgresql-contrib
sudo service postgresql start
```

---

### **2️⃣ Create the Database**
Open the **PostgreSQL interactive shell**:

```sh
psql -U postgres
```

Then, inside the `psql` shell:

```sql
CREATE DATABASE ipl_db;
```

Exit the `psql` shell with:
```sh
\q
```

---

### **3️⃣ Clone the Repository**
Clone the SQL Premier League backend repository:

```sh
git clone https://github.com/yourusername/sql-premier-league-backend.git
cd sql-premier-league-backend
```

---

### **4️⃣ Configure Environment Variables**
Create a **`.env`** file in the project root and add:

```ini
DATABASE_URL=postgresql://postgres:password@localhost:5432/ipl_db
```

> **Note:** Replace `"password"` with your actual **PostgreSQL password**.

---

### **5️⃣ Setup Virtual Environment**
Create and activate a **Python virtual environment**:

```sh
python3 -m venv venv
source venv/bin/activate  # Mac/Linux
venv\Scripts\activate     # Windows
```

---

### **6️⃣ Install Dependencies**
Inside the activated virtual environment, install dependencies:

```sh
pip install -r requirements.txt
```

---

### **7️⃣ Apply Migrations**
Run the following command to create the necessary tables:

```sh
python migrate.py
```

OR, if using **Flask-Migrate**:

```sh
flask db upgrade
```

---

### **8️⃣ Import IPL Data**
Run:

```sh
psql -U postgres -d ipl_db -f init.sql
```

If inside the `psql` shell:

```sql
\c ipl_db;
-- Paste the contents of init.sql here
```

> This imports the IPL dataset into your PostgreSQL database.

---

### **9️⃣ Run the Server**
Finally, start the Flask backend:

```sh
python app.py
```

If successful, the API should be running at:

```
http://127.0.0.1:5000
```

🎉 **You're now ready to contribute!** 🚀

---

## **📌 Verifying the Setup**
Check if PostgreSQL is running:

```sh
pg_isready
```

List all available databases:

```sh
psql -U postgres -c "\l"
```

Check if `ipl_db` exists:

```sh
psql -U postgres -d ipl_db -c "\dt"
```

---

If you have any questions, open an **issue on GitHub** or reach out in **Discussions**! 🎉

# EcommerceApp

[![Python](https://img.shields.io/badge/Python-3.x-blue?logo=python)](https://www.python.org/)
[![Django](https://img.shields.io/badge/Django-4.x-green?logo=django)](https://www.djangoproject.com/)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue?logo=docker)](https://www.docker.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A Django-based e-commerce application with modular apps for cart, home, order, product, and review management.  
This project is container-ready with Docker support and follows a service-based architecture.

---

## 📦 Project Structure
EcommerceApp/
── db/ # Database-related files or scripts
── ecommerce_cart/ # Cart management app
── ecommerce_home/ # Home/landing page app
── ecommerce_order/ # Order processing app
── ecommerce_product/ # Product listing & details app
── ecommerce_review/ # Product review & ratings app
── .gitignore # Ignored files & folders
── docker-compose.yml # Docker configuration
── README.md # Project documentation


---

## ✨ Features
- **User-friendly product browsing** – View products by search.
- **Cart Management** – Add, update, remove and clear items from the cart.
- **Order Processing** – Place orders and view order history.
- **Product Reviews & Ratings** – Create, edit, delete, vote on reviews.
- **Modular Django Apps** – Each major feature is an independent app.
- **Docker Ready** – Easily deploy using Docker Compose.

---

## 🛠️ Technologies Used
- **Backend:** Python 3, Django
- **Database:** PostgreSQL
- **Frontend:** HTML, CSS, Javascript (templates)
- **Containerization:** Docker & Docker Compose

---

### 1️⃣ Clone the Repository
```bash
git clone https://github.com/vamsigurajala/EcommerceApp.git
cd EcommerceApp
```
## 🚀 Installation & Setup

1. Create a Virtual Environment, if you cant install requirements mentioned
in the project..just install python 11 and use this command (python3.11 -m venv venv)
   
python -m venv venv
# Windows
venv\Scripts\activate
# macOS/Linux
source venv/bin/activate

2.  Install Dependencies
 pip install -r requirements.txt

3. In Pgadmin(Postgres) cretae a server and databases which should match db names in settings.py
    Apply Migrations
   command: python manage.py makemigrations
            python manage.py migrate  

4. Run the Development Server
   - python manage.py runserver
   - Now visit: http://127.0.0.1:8000/ in your browser.

5. Running with Docker
  - docker-compose up --build

📌 API Endpoints (Review Service Example)
POST /api/reviews/ – Create a review
PUT /api/reviews/<id>/ – Edit a review
DELETE /api/reviews/<id>/ – Delete a review
PATCH /api/reviews/<id>/vote/ – Vote on a review

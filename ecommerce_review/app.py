from flask import Flask, request, jsonify, redirect
import requests, json
from flask.templating import render_template
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from flask_migrate import Migrate
from sqlalchemy import DateTime
from marshmallow import Schema, fields
import psycopg2
import psycopg2.extras

user_url = 'http://127.0.0.1:8000'
product_url = 'http://127.0.0.1:8001'
cart_url = 'http://127.0.0.1:8002'
order_url ='http://127.0.0.1:8003'
review_url = 'http://127.0.0.1:8004'
#PRODUCT_SERVICE_URL = f'http://127.0.0.1:8001/api/singleproduct/{["product_id"]}'

app=Flask(__name__)
app.debug = True

app.config[ "SQLALCHEMY_DATABASE_URI"]="postgresql://postgres:2523@localhost:5432/review"
# app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db=SQLAlchemy(app)
migrate = Migrate(app, db)
ma = Marshmallow(app)

class Review(db.Model):
    review_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(100))
    product_id = db.Column(db.String(100))
    content = db.Column(db.String(255))
    posted_on = db.Column(db.DateTime)
    rating = db.Column(db.Integer)

    @classmethod
    def get_all(cls):
        return cls.query.all()



class ReviewSchema(Schema):
    class Meta:
        model = Review  
    
    review_id = fields.Integer()
    user_id = fields.String()
    product_id= fields.String()
    content = fields.String()
    posted_on =  fields.DateTime()
    rating =  fields.Float()

 

# @app.route("/see_reviews/", methods=["GET"])
# def see_reviews():
#     review_data = Review.get_all()
#     serializer = ReviewSchema(many=True)
#     data = serializer.dump(review_data)
#     return jsonify(data)

@app.route("/review/", methods=["POST"])
def add_review():
    data = request.get_json()
    user_id = requests.get(f'{user_url}/api/userview/', cookies=request.cookies).json()["user_id"]
    product_id = data["product_id"]
    content = data["content"]
    posted_on = data["posted_on"]  
    rating = int(data["rating"])
    review = Review(user_id=user_id, product_id=product_id, content=content, posted_on=posted_on, rating=rating)
    print(data)
    db.session.add(review)
    db.session.commit()
    return jsonify({'message': 'Review created successfully.'}), 201


@app.route('/reviews', methods=['GET'])
def get_reviews():
    product_id = request.get('product_id')
    reviews = Review.query.filter_by(product_id=product_id).all()
    response = []
    for review in reviews:
        response.append({
            'review_id': review.id,
            'product_id': review.product_id,
            'user_id': review.user_id,
            'content': review.content,
            'rating': review.rating,
        })
    return jsonify(response), 200

if __name__ == '__main__':
    app.run(debug=True, port=8004)


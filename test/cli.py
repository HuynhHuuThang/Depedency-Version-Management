from flask import Flask, request, jsonify, render_template
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///calculations.db'
db = SQLAlchemy(app)

# Database model to store calculations
class Calculation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    a = db.Column(db.Float, nullable=False)
    b = db.Column(db.Float, nullable=False)
    result = db.Column(db.Float, nullable=False)

# Create the database tables
with app.app_context():
    db.create_all()

@app.route('/calculate', methods=['POST'])
def calculate_sum():
    try:
        # Get values from request
        data = request.get_json()
        a = float(data['a'])
        b = float(data['b'])
        
        # Calculate sum
        result = a + b
        
        # Save to database
        new_calculation = Calculation(a=a, b=b, result=result)
        db.session.add(new_calculation)
        db.session.commit()
        
        # Return result
        return jsonify({
            'success': True,
            'result': result,
            'a': a,
            'b': b
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400
@app.route('/')
def index():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
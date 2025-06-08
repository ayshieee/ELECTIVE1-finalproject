from . import db
from flask_login import UserMixin
from sqlalchemy.sql import func


class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    data = db.Column(db.String(10000))
    date = db.Column(db.DateTime(timezone=True), default=func.now())
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True)
    password = db.Column(db.String(150))
    first_name = db.Column(db.String(150))
    notes = db.relationship('Note')

class Student(db.Model):
    id = db.Column(db.Integer, primary_key=True)   
    student_id = db.Column(db.String(50), unique=True, nullable=False)
    student_id_signature = db.Column(db.String(500), nullable=False)
    name = db.Column(db.String(150), nullable=False) 
    name_signature = db.Column(db.String(500), nullable=False)
    middle_name = db.Column(db.String(150), nullable=True)  
    middle_name_signature = db.Column(db.String(500), nullable=True)
    last_name = db.Column(db.String(150), nullable=False)  
    last_name_signature = db.Column(db.String(500), nullable=False)
    suffix = db.Column(db.String(50), nullable=True) 
    suffix_signature = db.Column(db.String(500), nullable=True)
    birthday = db.Column(db.String(10), nullable=False)
    birthday_signature = db.Column(db.String(500), nullable=False)
    age = db.Column(db.Integer, nullable=False) 
    age_signature = db.Column(db.String(500), nullable=False)  
    sex = db.Column(db.String(20), nullable=False) 
    sex_signature = db.Column(db.String(500), nullable=False)
    house_number = db.Column(db.String(50), nullable=False)
    house_number_signature = db.Column(db.String(500), nullable=False)
    street = db.Column(db.String(150), nullable=False)
    street_signature = db.Column(db.String(500), nullable=False)
    city = db.Column(db.String(150), nullable=False)
    city_signature = db.Column(db.String(500), nullable=False)
    state = db.Column(db.String(150), nullable=False)
    state_signature = db.Column(db.String(500), nullable=False)
    zip_code = db.Column(db.String(20), nullable=False)
    zip_code_signature = db.Column(db.String(500), nullable=False)
    country = db.Column(db.String(150), nullable=False)
    country_signature = db.Column(db.String(500), nullable=False)
    contact_number = db.Column(db.String(20), nullable=False) 
    contact_number_signature = db.Column(db.String(500), nullable=False)
    lrn = db.Column(db.String(12), unique=True, nullable=True) 
    lrn_signature = db.Column(db.String(500), nullable=True)
    course_year_level = db.Column(db.String(100), nullable=False) 
    course_year_level_signature = db.Column(db.String(500), nullable=False)
    college = db.Column(db.String(150), nullable=False)  
    college_signature = db.Column(db.String(500), nullable=False)
    plm_email = db.Column(db.String(150), unique=True, nullable=False) 
    plm_email_signature = db.Column(db.String(500), nullable=False)
    registration_status = db.Column(db.String(50), nullable=False)  
    registration_status_signature = db.Column(db.String(500), nullable=False)

    def to_dict(self):
        return {
            "id": self.id,
            "student_id": self.student_id,
            "name": self.name,
            "middle_name": self.middle_name,
            "last_name": self.last_name,
            "suffix": self.suffix,
            "birthday": self.birthday,
            "age": self.age,
            "sex": self.sex,
            "house_number": self.house_number,
            "street": self.street,
            "city": self.city,
            "state": self.state,
            "zip_code": self.zip_code,
            "country": self.country,
            "contact_number": self.contact_number,
            "lrn": self.lrn,
            "course_year_level": self.course_year_level,
            "college": self.college,
            "plm_email": self.plm_email,
            "registration_status": self.registration_status
        }
 
        
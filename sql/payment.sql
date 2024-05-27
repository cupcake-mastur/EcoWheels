CREATE DATABASE IF NOT EXISTS eco_wheels;

USE eco_wheels;

CREATE TABLE IF NOT EXISTS orders (
    order_id INT AUTO_INCREMENT PRIMARY KEY,
    fullname VARCHAR(255),
    email VARCHAR(255),
    address VARCHAR(255),
    city VARCHAR(100),
    state VARCHAR(100),
    zip_code VARCHAR(20),
    card_name VARCHAR(255),
    card_number VARCHAR(20),
    exp_month VARCHAR(20),
    exp_year VARCHAR(4),
    cvv VARCHAR(5)
);

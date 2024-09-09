import mysql.connector
import pandas as pd
import joblib
import csv
import random
from io import StringIO
from flask import Flask, render_template, url_for, redirect, flash, session, Response, request
from info import RegisterForm, LoginForm, FraudDetectionForm, OTPForm
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from datetime import datetime
import smtplib
from email.mime.text import MIMEText
import datetime as dt
import random

# run below code if database is not present 👇       in the field of password put your mysql password
# # Create the database
# mydb = mysql.connector.connect(host="localhost", user="root", password="My@123prad")
# mycursor = mydb.cursor()
# database_name = "fraud_detection"

# mycursor.execute(f"CREATE DATABASE {database_name}")
# print(f"The database '{database_name}' has been created.")
# # Use the database
# mycursor.execute(f"USE {database_name}")

# --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
mydb = mysql.connector.connect(host="localhost", user="root", password="Mysql@2003", database="cognizant")

mycursor = mydb.cursor()
table = "person_data"
table1 = "real_time_data"
# Check if the person_data exist
query = "SHOW TABLES LIKE %s"
mycursor.execute(query, (table,))
result = mycursor.fetchone()

# Create the person_data if it does not exist
if result:
    print(f"'{table}' is present.'")
else:
    if not result:
        mycursor.execute(f"CREATE TABLE {table} (id INT AUTO_INCREMENT PRIMARY KEY, username VARCHAR(255) NOT NULL, email VARCHAR(255) NOT NULL, password VARBINARY(255) NOT NULL)")
        print(f"The table '{table}' has been created.")
        mydb.commit()

# Check if the table 'real_time_data' exists
table1 = "real_time_data"
mycursor.execute(query, (table1,))
result1 = mycursor.fetchone()

# Create the 'real_time_data' table if it does not exist
if result1:
    print(f"'{table1}' is present.")
else:
    mycursor.execute(f"""CREATE TABLE {table1} (id INT AUTO_INCREMENT PRIMARY KEY, date DATE NOT NULL, transaction_id VARBINARY(255) NOT NULL UNIQUE,account_id VARBINARY(255) NOT NULL, 
                        day_of_week VARCHAR(50) NOT NULL, time INT NOT NULL,type_of_card VARCHAR(50) NOT NULL, entry_mode VARCHAR(50) NOT NULL, amount FLOAT NOT NULL, 
                        type_of_transaction VARCHAR(50) NOT NULL,merchant_group VARCHAR(50) NOT NULL,country_of_transaction VARCHAR(50) NOT NULL,
                        country_of_residence VARCHAR(50) NOT NULL,bank VARCHAR(50) NOT NULL, prediction INT(1) NOT NULL)""")
    print(f"The table '{table1}' has been created.")
    mydb.commit()



#........................Encryption.............................
def key_generate():
    salt = b'\xcf\x87\xfb\xfd\x1c\xbbx\xa7'
    password= 'not known'
    key = PBKDF2(password, salt, dkLen=8)
    return key

def  Encrypt(password):
    key = key_generate()
    cipher = DES.new(key, DES.MODE_ECB)
    # Encrypt the password
    padded_password = pad(password.encode(), DES.block_size)
    enc_pass = cipher.encrypt(padded_password)
    return enc_pass 

#........................Decryption.............................
def Decrypt(password):
    key = key_generate()

    cipher = DES.new(key, DES.MODE_ECB)
    # Decrypt the password
    decrypted_data = cipher.decrypt(password)
    unpadded_data = unpad(decrypted_data, DES.block_size).decode()
    return unpadded_data

# --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

app = Flask(__name__)
app.config['SECRET_KEY'] = "123456asamd"  # any password

# Main page 👇
@app.route("/")
def home():
    # Clear all session data when navigating to the home page
    session.clear()
    return render_template("index.html")



my_email = "spradnya0703@gmail.com"
password = "lwyv ogqr gabl ntld"  # Replace with your actual app password

def send_email(to_email, subject, body):
    with smtplib.SMTP("smtp.gmail.com", 587) as connection:
        connection.starttls()
        connection.login(user=my_email, password=password)
        message = f"Subject:{subject}\n\n{body}"
        connection.sendmail(from_addr=my_email, to_addrs=to_email, msg=message)



# Call the function to send OTP if today is Friday

def send_otp(email, otp):
    sender_email = "spradnya0703@gmail.com"
    sender_password = "lwyv ogqr gabl ntld"  
    
    # Set up the email content
    msg = MIMEText(f"Your OTP for login is: {otp}")
    msg['Subject'] = 'Your OTP Code'
    msg['From'] = sender_email
    msg['To'] = email

    # Send the email
    try:
        with smtplib.SMTP_SSL('smtp.gmail.com') as server:
            # server.starttls()
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, email, msg.as_string())
        print("OTP sent successfully")
    except Exception as e:
        print(f"Error sending OTP: {e}")

@app.route("/login", methods=["GET", "POST"])
def login_page():
    login_form = LoginForm()
    if login_form.validate_on_submit():
        epassword = Encrypt(login_form.password.data)
        query = f"SELECT * FROM {table} WHERE email = %s AND password = %s"
        mycursor.execute(query, (login_form.email.data, epassword))
        user = mycursor.fetchone()

        if user:
            session['user_id'] = user[0]
            otp = random.randint(100000, 999999)  # Generate a 6-digit OTP
            session['otp'] = otp  # Store the OTP in the session
            session['email'] = login_form.email.data  # Store the email in the session
            
            send_otp(login_form.email.data, otp)  # Send the OTP to the user's email
            
            return redirect(url_for('otp_verification'))
        else:
            return redirect(url_for('register_page'))
        
    return render_template('login.html', form=login_form)

@app.route("/otp_verification", methods=["GET", "POST"])
def otp_verification():
    form = OTPForm()
    
    if 'otp' not in session or 'email' not in session:
        return redirect(url_for('login_page'))
    
    if form.validate_on_submit():
        entered_otp = form.otp.data
        if int(entered_otp) == session['otp']:
            # OTP is correct, proceed to the main web page
            session.pop('otp')  # Remove OTP from session after successful verification
            return redirect(url_for('web_page'))
        else:
            flash("Invalid OTP. Please try again.")
    
    return render_template('otp_verification.html', form=form)



@app.route('/register', methods=["GET", "POST"])
def register_page():
    register_form = RegisterForm()
    if register_form.validate_on_submit():
        if register_form.password.data == register_form.re_password.data:
            epassword = Encrypt(register_form.password.data)
            # print(epassword)
            # Check if the email is already registered
            query = f"SELECT * FROM {table} WHERE email = %s"
            mycursor.execute(query, (register_form.email.data,))
            existing_user = mycursor.fetchone()

            if existing_user:
                # If email exists, redirect to login page with a flash message
                # flash("You are already registered. Please log in.")
                return redirect(url_for('login_page'))

            # Insert the new user record if email does not exist
            sql = f"INSERT INTO {table} (username, email, password) VALUES (%s, %s, %s)"
            val = (register_form.name.data, register_form.email.data, epassword)
            try:
                mycursor.execute(sql, val)
                mydb.commit()
                # After successful registration, redirect to the main web page
                session['user_id'] = mycursor.lastrowid  # Set user_id in session
                return redirect(url_for('web_page'))
            except Exception as e:
                print(f"Error inserting user: {e}")
                # flash("An error occurred while registering. Please try again.")
                return render_template("register.html", form=register_form)
        else:
            # flash("Passwords do not match!")
            return render_template("register.html", form=register_form)
    
    return render_template("register.html", form=register_form)


@app.route('/logout')
def logout():
    # Remove the user_id from the session
    session.pop('user_id', None)
    # Redirect to home page after logging out
    return redirect(url_for('home'))

@app.route('/about')
def about_us_page():
    return render_template('about_us.html')

@app.route('/vision')
def vision():
    return render_template('vision.html')

@app.route('/fraud_detection')
def fraud_detection():
    return render_template('fraud_detection_page.html')

@app.route('/analysis')
def analysis():
    return render_template('analysis.html')


# -------------------------------------------------------------------------------------------
import joblib
import pandas as pd

# Load the model
path = r'C:\Users\harsh\OneDrive\Desktop\Cognizant Final\Fraud Detection\fraud_detection_model.pkl'
pipeline = joblib.load(path)
paths = r'C:\Users\harsh\OneDrive\Desktop\Cognizant Final\Fraud Detection\CreditCardDataset.csv'
data = pd.read_csv(paths)
# Retrieve unique values for dropdowns and pass them to the template
data['Merchant Group'] = data['Merchant Group'].fillna('Unknown').astype(str)
days_of_week = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
card_types = sorted(data['Type of Card'].unique())
entry_modes = sorted(data['Entry Mode'].unique())
transaction_types = sorted(data['Type of Transaction'].unique())
merchant_groups = sorted(data['Merchant Group'].unique())
countries = sorted(data['Country of Transaction'].unique())
residences = sorted(data['Country of Residence'].unique())
banks = sorted(data['Bank'].unique())

# transaction ID generation
def generate_transaction_id():
    while True:
        transaction_id = str(random.choice([2, 3])) + ''.join([str(random.randint(0, 9)) for _ in range(6)])
        # check if the transaction ID already exists in the database
        query = f"SELECT COUNT(*) FROM {table1} WHERE transaction_id = %s"
        mycursor.execute(query, (transaction_id,))
        if mycursor.fetchone()[0] == 0:
            return transaction_id


@app.route('/main_web_page', methods=["GET", "POST"])
def web_page():
    form = FraudDetectionForm()
    if 'user_id' in session:
        return render_template("web_page.html", form=form, 
                                days_of_week=days_of_week,
                                card_types=card_types,
                                entry_modes=entry_modes,
                                transaction_types=transaction_types,
                                merchant_groups=merchant_groups,
                                countries=countries,
                                residences=residences,
                                banks=banks)
    else:
        return redirect(url_for('home'))

def mask_account_id(account_id, visible_digits=4):
    return '*' * (len(account_id) - visible_digits) + account_id[-visible_digits:]


@app.route('/show_data')
def show_data():
    query = "SELECT * FROM real_time_data"
    mycursor.execute(query)
    data = mycursor.fetchall()
    masked_data = []
    for row in data:
        date1 = row[1].strftime('%d-%m-%Y')
        transaction_id = Decrypt(row[2])
        account_id = mask_account_id(Decrypt(row[3]))
        
        masked_row = list(row)
        masked_row[1] = date1 
        masked_row[2] = transaction_id
        masked_row[3] = account_id 
        masked_data.append(tuple(masked_row))
    return render_template('show_data.html', data=masked_data)

@app.route('/delete/<int:id>', methods=['POST'])
def delete_data(id):
    try:
        delete_query = "DELETE FROM real_time_data WHERE id = %s"
        mycursor.execute(delete_query, (id,))
        mydb.commit()
    except Exception as e:
        print(f"Error deleting record: {e}")
    return redirect(url_for('show_data'))

@app.route('/download_csv')
def download_csv():
    try:
        query = "SELECT * FROM real_time_data"
        mycursor.execute(query)
        rows = mycursor.fetchall()

        # Create a CSV file in memory
        si = StringIO()
        writer = csv.writer(si)
        writer.writerow(['Serial No.', 'Date', 'Transaction ID', 'Account ID', 'Day of Week', 'Time', 'Type of Card', 'Entry Mode', 'Amount', 'Type of Transaction',
                         'Merchant Group', 'Country of Transaction', 'Country of Residence', 'Bank', 'Prediction'])

        for index, row in enumerate(rows, start=1):
            transaction_id = Decrypt(row[2])
            account_id = Decrypt(row[3])
            writer.writerow([index] + [row[1]] + [transaction_id]+ [account_id] + list(row[4:]))

        # Set up the response
        output = Response(si.getvalue(), mimetype='text/csv')
        output.headers['Content-Disposition'] = 'attachment; filename=real_time_data.csv'

        return output
    except Exception as e:
        print(f"Error generating CSV: {e}")
        flash("An error occurred while generating the CSV file. Please try again.", "danger")
        return redirect(url_for('show_data'))

@app.route('/download_fraud_csv')
def download_fraud_csv():
    try:
        query = "SELECT * FROM real_time_data WHERE Prediction = 1"
        mycursor.execute(query)
        rows = mycursor.fetchall()

        # Create a CSV file in memory
        si = StringIO()
        writer = csv.writer(si)
        writer.writerow(['Serial No.', 'Date', 'Transaction ID', 'Account ID', 'Day of Week', 'Time', 'Type of Card', 'Entry Mode', 'Amount', 'Type of Transaction',
                         'Merchant Group', 'Country of Transaction', 'Country of Residence', 'Bank', 'Prediction'])

        for index, row in enumerate(rows, start=1):
            transaction_id = Decrypt(row[2])
            account_id = Decrypt(row[3])
            writer.writerow([index] + [row[1]] + [transaction_id, account_id] + list(row[4:]))

        # Set up the response
        output = Response(si.getvalue(), mimetype='text/csv')
        output.headers['Content-Disposition'] = 'attachment; filename=fraud_data.csv'

        return output
    except Exception as e:
        print(f"Error generating CSV: {e}")
        flash("An error occurred while generating the fraud CSV file. Please try again.", "danger")
        return redirect(url_for('show_data'))





@app.route('/predict', methods=['POST'])
def predict():
    form = FraudDetectionForm()
    if form.validate_on_submit():
        transaction_id = Encrypt(generate_transaction_id())
        account_id = Encrypt(form.account_id.data)
        
        data = {
            'Day of Week': form.day.data,
            'Time': form.time.data,
            'Type of Card': form.card_type.data,
            'Entry Mode': form.entry_mode.data,
            'Amount': form.amount.data,
            'Type of Transaction': form.transaction_type.data,
            'Merchant Group': form.merchant_group.data,
            'Country of Transaction': form.country.data,
            'Country of Residence': form.residence.data,
            'Bank': form.bank.data,
        }
        input_df = pd.DataFrame([data])

        # Insert data into the 'real_time_data' table
        insert_query = f"""INSERT INTO real_time_data (date, transaction_id, account_id, day_of_week, time, type_of_card, entry_mode, amount, type_of_transaction, merchant_group, 
                            country_of_transaction, country_of_residence, bank, prediction) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"""

        # Make prediction
        try:
            prediction = pipeline.predict(input_df)
            values = (
            form.date.data,
            transaction_id,
            account_id,
            data['Day of Week'],
            data['Time'],
            data['Type of Card'],
            data['Entry Mode'],
            data['Amount'],
            data['Type of Transaction'],
            data['Merchant Group'],
            data['Country of Transaction'],
            data['Country of Residence'],
            data['Bank'],
            int(prediction[0]))

            mycursor.execute(insert_query, values)
            mydb.commit()
            return render_template('result.html', prediction=prediction[0])
        except Exception as e:
            print(f"Prediction error: {e}")
            return render_template('error.html', error_message="An error occurred during prediction. Please try again.")
    print("Form errors:", form.errors)
    return redirect(url_for('web_page'))


# -------------------------------------------------------------------------------------------


if __name__ =="__main__":
    app.run(debug=True, port=5002)


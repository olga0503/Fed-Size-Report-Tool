import pandas as pd
import numpy as np


from datetime import datetime
from fedsize import app, db, bcrypt
from flask_bcrypt import Bcrypt
from flask import render_template, url_for, flash, redirect, request, session, send_from_directory
from fedsize.forms import RegistrationForm, LoginForm
from fedsize.models import User
from flask_login import login_user, current_user, logout_user, login_required
from werkzeug.utils import secure_filename
import os



UPLOAD_FOLDER = '/path/to/the/uploads'


app.config['IMAGE_UPLOADS'] = "/Users/olyafomicheva/desktop/fedsize_report/fedsize/uploads"
app.config["ALLOWED_IMAGE_EXTENSIONS"] = ["CSV","XLS","XLSX"]
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024



def allowed_file(filename):

    if not "." in filename:
        return False

    ext = filename.rsplit(".", 1)[1]

    if ext.upper() in app.config["ALLOWED_IMAGE_EXTENSIONS"]:
        return True
    else:
        return False

def check_csv(filename):

    ext = filename.rsplit(".", 1)[1]

    if ext.upper() in ["CSV"]:
        return True
    else:
        return False


def allowed_image_filesize(filesize):

    if int(filesize) <= app.config["MAX_IMAGE_FILESIZE"]:
        return True
    else:
        return False


@app.route("/")
@app.route("/home", methods=["GET", "POST"])
@login_required
def home():
    
    
                         
    return render_template("upload_file.html")




@app.route("/login", methods=['GET', 'POST'])
def login():

    users = pd.read_csv(os.path.join(app.config["IMAGE_UPLOADS"], 'users.csv'))

    x=bcrypt.generate_password_hash("fedsize").decode('utf-8')
    #x=bcrypt.check_password_hash(up, 'fedsize')

    if current_user.is_authenticated:
        return redirect(url_for('uploader'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
            return redirect('/')

    return render_template('login.html', title='Login', form=form)





@app.route("/uploader", methods=["GET", "POST"])
def uploader():
    

    
    if request.method == "POST":

        if request.files:

            file = request.files["file"]
            

            if file.filename == '':
               flash('No file selected for uploading')
               return redirect('/')
                        
            if not allowed_file(file.filename):
                    flash('Unsupported file type')
                    return redirect('/')

               
            filename = secure_filename(file.filename)



            path = os.path.join(app.config["IMAGE_UPLOADS"], filename)

            file.save(path)


            session['file_path'] = path
            session['filename'] = filename

            if not check_csv(filename):
                upl_file = pd.read_excel(path,sheetname="Sheet1",index_col=None)
            else:
                upl_file = pd.read_csv(path)
                
            upl_file.to_csv(os.path.join(app.config["IMAGE_UPLOADS"], filename), index=False)
    
            columns = list(upl_file.columns)    
            session['file_columns'] = columns

            
           
            #return send_from_directory('/Users/FOMIOLNY/desktop/flask_test/uploads', filename='xxx.csv', as_attachment=True)
            #return render_template("xx.html",title='ccc', labels=bar_labels, values=bar_values, max=100)

        return render_template("upload.html", filename = filename, columns = columns)

    if request.method == "GET":

        filename = session.get('filename')
        columns = session.get('file_columns')

        return render_template("upload.html", filename = filename, columns = columns)
    
    

            





@app.route('/federation_by_size/<string:size>', methods=["GET", "POST"])
def federation_by_size(size):
    
    s = size
    
    session['s'] = s


    path = session.get('file_path')
    bar_labels = session.get('bar_labels')

    m = pd.read_csv(path)
    
    city_size_num = pd.DataFrame(m.groupby('City-Size')['First Name'].count()).reset_index() 

    x = m.groupby('City-Size')
    y = x.get_group(size)
    num = y.shape[0]

    return render_template("federation_by_size.html",tables=[y.to_html(classes='table-sticky sticky-enabled', index=False)], fed_sizes=city_size_num, num=num)



@app.route('/federation_by_size_all', methods=["GET", "POST"])
def federation_by_size_all():

   
    
    path = session.get('file_path')
    filename = session.get('filename')
    columns = session.get('file_columns')

    feds = pd.read_csv(os.path.join(app.config["IMAGE_UPLOADS"], 'federations.csv'))
    feds['City-Size'] = feds['City-Size'].replace(['1Large','3Inter','2LrgeInter','5SmallFed'],['Large','Intermidiate','Large Intermidiate','Small'])

    upl_file = pd.read_csv(path)   


    merge_field = request.form.get('field') 

    report = upl_file.merge(feds, left_on=merge_field, right_on='Community')

    cols = list(report)
    # move the column to head of list using index, pop and insert
    cols.insert(0, cols.pop(cols.index('City-Size')))
    cols.insert(1, cols.pop(cols.index('Federation Name ')))
    
    report=report[cols]
    report.to_csv(path, index=False)
    
    city_size_num = pd.DataFrame(report.groupby('City-Size')['First Name'].count()).reset_index() 
    r=pd.read_csv(path) 
    

    #form = Form()
    #form.city.choices = [row for index, row in city_size_num.iterrows()]

    return render_template("federation_by_size_all.html",tables=[report.to_html(classes='table-sticky sticky-enabled',index=False)], fed_sizes=city_size_num, columns=columns, r=r, filename=filename)    



@app.route('/analysis', methods=["GET", "POST"])
def analysis():
    

    

    x = session.get('x')
    m=pd.read_csv(x)
    columns=list(m.columns)
    

    #y=pd.DataFrame(m.groupby(g[0])[g[1]].count()).reset_index()
    #y.to_csv(os.path.join(app.config["IMAGE_UPLOADS"], 'xx2.csv'), index=False)

    #return send_from_directory('/Users/FOMIOLNY/desktop/flask_test/uploads', filename='xx2.csv', as_attachment=True)
    #return render_template("xxxxx.html", g=g[0])
    return render_template("analysis.html", columns = columns)


@app.route('/analysis_report', methods=["GET", "POST"])
def analysis_report():
    

    g=request.form.getlist('field')
    gg =request.form.get('select2')

    x = session.get('x')
    m=pd.read_csv(x)
    columns=list(m.columns)
    

    y=pd.DataFrame(m.groupby(g)[gg].count()).reset_index()
    y.to_csv(os.path.join(app.config["IMAGE_UPLOADS"], 'xx5.csv'), index=False)

    filename = session.get('filename')

    #return send_from_directory('/Users/FOMIOLNY/desktop/flask_test/uploads', filename='xx2.csv', as_attachment=True)
    #return render_template("xxxxx.html", g=g[0])
    return render_template("_test.html", tables=[y.to_html(classes='table-sticky sticky-enabled',index=False)])


   

@app.route('/feds', methods=['GET', 'POST'])
def animals():
    selected_animal = request.args.get('type')
    return render_template(animals.html, title='Animal Details', animal=selected_animal)
    

    


@app.route("/download", methods=["GET", "POST"])
def download():

        #if request.method == 'GET':

        filename = session.get('filename')
        filepath = session.get('file_path')

        s = session.get('s')
        
       
        x = session.get('x')
        m = pd.read_csv(filepath)

        report = m[m['City-Size']==s]
        report.to_csv(os.path.join(app.config["IMAGE_UPLOADS"], filename.rsplit(".", 1)[0]+"_"+s+"."+filename.rsplit(".", 1)[1]), index=False)

        return send_from_directory(app.config["IMAGE_UPLOADS"], filename=filename.rsplit(".", 1)[0]+"_"+s+"."+filename.rsplit(".", 1)[1], as_attachment=True)
        #return render_template("xxx.html",s=s)
    
             

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('home'))





@app.route("/about")
def about():
    return render_template('about.html', title='About')





if __name__ == '__main__':
    db.create_all()
    app.run(debug=False)
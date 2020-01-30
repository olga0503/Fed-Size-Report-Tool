import pandas as pd
import numpy as np

from datetime import datetime
import time, xlrd, xlwt, os, time
from fedsize import app, db, bcrypt
from flask_bcrypt import Bcrypt
from flask import render_template, url_for, flash, redirect, request, session, send_from_directory
from fedsize.forms import RegistrationForm, LoginForm
from fedsize.models import User
from flask_login import login_user, current_user, logout_user, login_required
from werkzeug.utils import secure_filename


#UPLOAD_FOLDER = '/path/to/the/uploads'

app.config['UPLOADS'] = "/report-tool/fedsize/uploads"
#"/Users/olyafomicheva/desktop/fedsize_report/fedsize/uploads"

app.config['UPLOADS_XLS'] = "/report-tool/fedsize/uploads/xls"
#"/Users/olyafomicheva/desktop/fedsize_report/fedsize/uploads/xls"

app.config['UPLOADS_SIZE'] = "/report-tool/fedsize/uploads/size"
#"/Users/olyafomicheva/desktop/fedsize_report/fedsize/uploads/size"

app.config['FED_UPLOADS'] = "/report-tool/fedsize/federations"
# "/Users/olyafomicheva/desktop/fedsize_report/fedsize/federations"

app.config["ALLOWED_FILE_EXTENSIONS"] = ["CSV", "XLS", "XLSX"]
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024

db.create_all()


#validates file extention
def allowed_file(filename):

    if not "." in filename:
        return False

    ext = filename.rsplit(".", 1)[1]

    if ext.upper() in app.config["ALLOWED_FILE_EXTENSIONS"]:
        return True
    else:
        return False

#checks wether file is in csv format or not
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
#user login
def login():
    x = bcrypt.generate_password_hash("fedsize").decode('utf-8')
    # x=bcrypt.check_password_hash(up, 'fedsize')

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
            return redirect('/login')

    return render_template('login.html', title='Login', form=form)


@app.route("/uploader", methods=["GET", "POST"])
#function that allows user to upload file to the system
def uploader():
    if request.method == "POST":

        if request.files:

            file = request.files["file"]

            #verifies that filename is not blank
            if file.filename == '':
                    flash('No file selected or uploading')
                    return redirect('/')

            #verifies file type
            if not allowed_file(file.filename):
                    flash('Unsupported file type')
                    return redirect('/')


            filename = secure_filename(file.filename)

            #saves original filename to session
            org_filename = filename
            session['org_filename'] = filename

            #appends timestamp to filename
            filename = filename.rsplit(".", 1)[0] + "_" + time.strftime("%B-%d-%H:%M:%S") + "." + filename.rsplit(".", 1)[1]

            path = os.path.join(app.config["UPLOADS"], filename)

            #saves file
            file.save(path)

            #save file path and filename to sessions
            session['file_path'] = path
            session['filename'] = filename

            #verifies csv format
            if not check_csv(filename):
                try:
                    #read excel file
                    upl_file = pd.read_excel(path, sheet_name = 0)


                except:
                    flash('Unsupported file type')
                    return redirect('/')

            else:
                try:
                    #read csv
                    upl_file = pd.read_csv(path)
                    session['file_path'] = os.path.join(app.config["UPLOADS_XLS"],
                                                   filename.rsplit(".", 1)[0] + ".xls")
                    #save csv as xls
                    upl_file.to_excel(path, index=False)

                except:
                    flash('Unsupported file type')
                    return redirect('/')

            #counts the number of records in uploaded file
            session['records_num'] = upl_file.shape[0]

            #save file columns names
            columns = list(upl_file.columns)
            session['file_columns'] = columns

            # return send_from_directory('/Users/FOMIOLNY/desktop/flask_test/uploads', filename='xxx.csv', as_attachment=True)
            # return render_template("xx.html",title='ccc', labels=bar_labels, values=bar_values, max=100)

        return render_template("upload.html", filename=org_filename, columns=columns)

    else:

        #read filename and file columns names
        filename = session.get('filename')
        columns = session.get('file_columns')

        return render_template("upload.html", filename=org_filename, columns=columns)




@app.route("/add_fed_file", methods=["GET", "POST"])
def add_fed_file():

    feds = pd.read_csv(os.path.join(app.config["UPLOADS"], 'federations.csv'))
    federations = list(set(feds['Federation Name']))
    size_types = list(set(feds['City-Size']))




    return render_template("_test.html", tables=[feds.to_html(classes='table-sticky sticky-enabled', index=False)],
                           federations=federations, size_types=size_types)


@app.route("/add_fed_file2", methods=["GET", "POST"])
def add_fed_file2():
    feds = pd.read_csv(os.path.join(app.config["UPLOADS"], 'federations.csv'))

    data = request.form["emailx"]
    return render_template("_test.html", tables=[feds.to_html(classes='table-sticky sticky-enabled', index=False)],
                           data=data)


@app.route('/federation_by_size/<string:size>', methods=["GET", "POST"])
def federation_by_size(size):

    #save fed size to session
    session['fed_size'] = size

    #read file name from session
    filename = session.get('filename')

    #read file_path from session
    path = session.get('file_path')

    m = pd.read_excel(path, sheet_name=0)


    report = m[m['City-Size'] == size]
    report.to_excel(os.path.join(app.config["UPLOADS_SIZE"],
                                 filename.rsplit(".", 1)[0] + "_" + size + "_.xls"), index=False)

    #if 'First Name' in city_size_num.columns:
    city_size_num = pd.DataFrame(m.groupby('City-Size').size().reset_index(name="counts"))

    x = m.groupby('City-Size')
    y = x.get_group(size)
    num = y.shape[0]

    return render_template("federation_by_size.html",
                           tables=[y.to_html(classes='table-sticky sticky-enabled', index=False)],
                           fed_sizes=city_size_num, num=num,
                           records_num=session.get('records_num'))


@app.route('/federation_by_size_all', methods=["GET", "POST"])
#function that displays all file records
def federation_by_size_all():

    if request.method == "POST":

        #read file variables
        path = session.get('file_path')
        filename = session.get('filename')
        columns = session.get('file_columns')

        #read federations file
        feds = pd.read_csv(os.path.join(app.config["UPLOADS"], 'federations.csv'))

        #read uploaded file
        upl_file = pd.read_excel(path, sheet_name = 0)



        #get selected field
        merge_field = request.form.get('field')

        if ('City-Size' in columns) and (merge_field!='City-Size'):
            upl_file.drop(columns=['City-Size'], inplace=True)

        #remove dots and commas from communities
        upl_file[merge_field] = upl_file[merge_field].str.title()
        upl_file[merge_field] = upl_file[merge_field].str.replace('.','')
        upl_file[merge_field] = upl_file[merge_field].str.replace(',','')

        #capitalize comminities titles
        feds['Community'] = feds['Community'].str.title()

        #merge two data frames
        report = upl_file.merge(feds, left_on=merge_field, right_on='Community', how='left')
        #save merged data set
        report.to_excel(os.path.join(app.config["UPLOADS_XLS"],filename), index=False)



        #replace NaNs communities with 'None'
        if 'City-Size' in report.columns:
            report['City-Size'].fillna('None', inplace=True)

        #replace NaNs records with blanks
        report = report.replace(np.nan, ' ', regex=True)

        #read data set columns
        cols = list(report)


        if merge_field in cols:
            # move the column to head of list using index, pop and insert
            cols.insert(0, cols.pop(cols.index(merge_field)))


        if 'City-Size' in cols:
            cols.insert(1, cols.pop(cols.index('City-Size')))

            report = report[cols]
            report.to_excel(path, index=False)

            path_city_size_num = os.path.join(app.config["UPLOADS"], "city_size_num_" + time.strftime("%B-%d-%H-%M-%S") + ".csv")
            session["path_city_size_num"] = path_city_size_num

            city_size_num.to_csv(path_city_size_num, index=False)
            
        else:
            city_size_num = pd.DataFrame()



        return render_template("federation_by_size_all.html",
                               tables=[report.to_html(classes='table-sticky sticky-enabled', index=False)],
                               fed_sizes=city_size_num, columns=columns, filename=filename,
                               records_num=session.get('records_num'))

    if request.method == "GET":
        path = session.get('file_path')
        filename = session.get('filename')
        columns = session.get('file_columns')

        report = pd.read_excel(path, index=False)
        city_size_num = pd.read_csv(session.get("path_city_size_num"))
        
        return render_template("federation_by_size_all.html",
                               tables=[report.to_html(classes='table-sticky sticky-enabled', index=False)],
                               fed_sizes=city_size_num, columns=columns, filename=filename,
                               records_num=session.get('records_num'))


@app.route('/analysis', methods=["GET", "POST"])
def analysis():
    x = session.get('x')
    m = pd.read_csv(x)
    columns = list(m.columns)

    # y=pd.DataFrame(m.groupby(g[0])[g[1]].count()).reset_index()
    # y.to_csv(os.path.join(app.config["IMAGE_UPLOADS"], 'xx2.csv'), index=False)

    # return send_from_directory('/Users/FOMIOLNY/desktop/flask_test/uploads', filename='xx2.csv', as_attachment=True)
    # return render_template("xxxxx.html", g=g[0])
    return render_template("analysis.html", columns=columns)


@app.route('/analysis_report', methods=["GET", "POST"])
def analysis_report():
    g = request.form.getlist('field')
    gg = request.form.get('select2')

    x = session.get('x')
    m = pd.read_csv(x)
    columns = list(m.columns)

    y = pd.DataFrame(m.groupby(g)[gg].count()).reset_index()
    y.to_csv(os.path.join(app.config["UPLOADS"], 'xx5.csv'), index=False)

    filename = session.get('filename')

    # return send_from_directory('/Users/FOMIOLNY/desktop/flask_test/uploads', filename='xx2.csv', as_attachment=True)
    # return render_template("xxxxx.html", g=g[0])
    return render_template("_test.html", tables=[y.to_html(classes='table-sticky sticky-enabled', index=False)])


@app.route('/feds', methods=['GET', 'POST'])
def animals():
    selected_animal = request.form.get('type')
    return render_template(animals.html, title='Animal Details', animal=selected_animal)


@app.route("/download", methods=["GET", "POST"])
def download():

    filename = session.get('filename')
    filepath = session.get('file_path')

    size = session.get('fed_size')


    return send_from_directory(app.config["UPLOADS_SIZE"], filename=filename.rsplit(".", 1)[0]+"_" + size + "_.xls",
                               attachment_filename = session.get('org_filename').rsplit(".", 1)[0] + "_" + size + "_" + time.strftime(
                                   "%B-%d-%H:%M:%S") + ".xls",
                               as_attachment=True)



@app.route("/download_all", methods=["GET", "POST"])
def download_all():
    # if request.method == 'GET':

    filename_x = session.get('filename')
    filepath = session.get('file_path')

    #report = pd.read_csv(filepath)

    #report.to_excel(os.path.join(app.config["IMAGE_UPLOADS"],
                             #    filename.rsplit(".", 1)[0]+"_"+time.strftime("%B-%d-%H:%M:%S") + ".xls"),
                   # index=False, sheet_name='Sheet1')

    return send_from_directory(app.config["UPLOADS_XLS"],
                               filename=filename_x,
                               attachment_filename=session.get('org_filename').rsplit(".", 1)[0]+"_" + time.strftime("%B-%d-%H:%M:%S") + "." + session.get('org_filename').rsplit(".", 1)[1], as_attachment=True)

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route("/about")
def about():
    return render_template('about.html', title='About')


@app.route("/reset_password", methods=['GET', 'POST'])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        send_reset_email(user)
        flash('An email has been sent with instructions to reset your password.', 'info')
        return redirect(url_for('login'))
    return render_template('reset_request.html', title='Reset Password', form=form)

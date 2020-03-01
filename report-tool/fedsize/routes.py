from json import JSONEncoder

import pandas as pd
import numpy as np

from datetime import datetime
import urllib
import time, xlrd, xlwt, os, time, json, requests
from fedsize import app, db, bcrypt
from flask_bcrypt import Bcrypt
from flask import render_template, url_for, flash, redirect, request, session, send_from_directory, jsonify
from fedsize.forms import RegistrationForm, LoginForm
from fedsize.models import User
from flask_login import login_user, current_user, logout_user, login_required
from werkzeug.utils import secure_filename

from elasticsearch import Elasticsearch

from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView


#UPLOAD_FOLDER = '/path/to/the/uploads'

app.config['ELASTICSEARCH_URL'] = "http://elasticsearch:9200/"
#"http://127.0.0.1:9200"

app.config['UPLOADS'] = "/report-tool/fedsize/uploads"
#"/Users/olyafomicheva/desktop/fedsize_report/fedsize/uploads"


app.config['UPLOADS_XLS'] = "/report-tool/fedsize/uploads/xls"
#"/Users/olyafomicheva/desktop/fedsize_report/fedsize/uploads/xls"

app.config['UPLOADS_SIZE'] = "/report-tool/fedsize/uploads/size"
#"/Users/olyafomicheva/desktop/fedsize_report/fedsize/uploads/size"

app.config['FED_UPLOADS'] = "/report-tool/fedsize/federations"
#"/Users/olyafomicheva/desktop/fedsize_report/fedsize/federations"

app.config["ALLOWED_FILE_EXTENSIONS"] = ["CSV", "XLS", "XLSX"]
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024

admin = Admin(app)
admin.add_view(ModelView(User, db.session))

db.create_all()

#capitalize comminities titles
feds = pd.read_csv(os.path.join(app.config["UPLOADS"], 'federations.csv'))
feds['Community'] = feds['Community'].str.title()
feds.to_csv(os.path.join(app.config["UPLOADS"], 'federations.csv'), index=False)



class AdminView(ModelView):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.static_folder = 'static'

    def is_accessible(self):

        return login.currrent_user.is_authincated

    def inaccessible_callback(self, name, **kwargs):
        if not self.is_accessible():
            return redirect(url_for('home', next=request.url))

es = Elasticsearch([app.config['ELASTICSEARCH_URL']])

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

        return render_template("upload.html", org_filename=org_filename, filename=filename, columns=columns)

    else:

        #read filename and file columns names
        filename = session.get('filename')
        org_filename = session.get('org_filename')
        columns = session.get('file_columns')

        return render_template("upload.html", org_filename=org_filename, filename=filename, columns=columns)




@app.route("/add_community", methods=["GET", "POST"])
def add_fed_file():


    feds = pd.read_csv(os.path.join(app.config["UPLOADS"], 'federations.csv'))
    federations = list(set(feds['Federation Name']))
    size_types = list(set(feds['City-Size']))

    # replace NaNs communities with 'None'
    if 'Notes' in feds.columns:
        feds['Notes'].fillna(' ', inplace=True)

    return render_template("_test.html", tables=[feds.to_html(classes='table-sticky sticky-enabled', index=False)],
                           federations=federations, size_types=size_types)

@app.route("/add_community2", methods=["GET", "POST"])
def add_community2():

    feds = pd.read_csv(os.path.join(app.config["UPLOADS"], 'federations.csv'))
    federations = list(set(feds['Federation Name']))
    size_types = list(set(feds['City-Size']))

    # replace NaNs communities with 'None'
    if 'Notes' in feds.columns:
        feds['Notes'].fillna(' ', inplace=True)

    x=pd.read_msgpack(session.get('data'))


    return render_template("_test.html", tables=[x.to_html(classes='table-sticky sticky-enabled', index=False)],
                           federations=federations, size_types=size_types, k=session.get('k'))


@app.route("/add_fed_file2", methods=["GET", "POST"])
def add_fed_file2():
    feds = pd.read_csv(os.path.join(app.config["UPLOADS"], 'federations.csv'))
    federations = list(set(feds['Federation Name']))
    size_types = list(set(feds['City-Size']))

    c_data = request.form.getlist("community")
    fedsize_data = request.form.getlist("fedsize")
    f_data = request.form.getlist("federation")
    n_data = request.form.getlist("note")

    new_record = pd.DataFrame({feds.columns[0]:c_data, feds.columns[1]:fedsize_data, feds.columns[2]:f_data, feds.columns[3]:n_data})
    new_record[feds.columns[0]] = new_record[feds.columns[0]].str.title()




    new_records = new_record.to_msgpack()
    session['new_record'] = new_records


    return render_template("_test.html", tables=[feds.to_html(classes='table-sticky sticky-enabled', index=False)],
                           federations=federations, size_types=size_types)

    #return render_template("_test.html", tables=[feds.to_html(classes='table-sticky sticky-enabled', index=False)],
                           #data=c_data, data2=fedsize_data,data3=f_data, data4=n_data)



@app.route("/add_community_confirm", methods=["GET", "POST"])
def add_community_confirm():

    feds = pd.read_csv(os.path.join(app.config["UPLOADS"], 'federations.csv'))
    federations = list(set(feds['Federation Name']))
    size_types = list(set(feds['City-Size']))

    c_data = request.form.getlist("community")
    fedsize_data = request.form.getlist("fedsize")
    f_data = request.form.getlist("federation")
    n_data = request.form.getlist("note")

    new_record = pd.DataFrame({feds.columns[0]: c_data, feds.columns[1]: fedsize_data, feds.columns[2]: f_data, feds.columns[3]: n_data})
    new_record[feds.columns[0]] = new_record[feds.columns[0]].str.title()

    feds = pd.read_csv(os.path.join(app.config["UPLOADS"], 'federations.csv'))
    federations = list(set(feds['Federation Name']))
    size_types = list(set(feds['City-Size']))


    k = []
    m = []

    for index, row in new_record.iterrows():
        if row[feds.columns[0]] in list(feds[feds.columns[0]]):
            k.append(row[feds.columns[0]])

        else:
            m.append(row[feds.columns[0]])

            #feds.drop(feds[feds[feds.columns[0]] == row[feds.columns[0]]].index, inplace=True)


    new_record = new_record.to_msgpack()
    session['new_record']= new_record

    return render_template("test2.html", tables=[feds.to_html(classes='table-sticky sticky-enabled', index=False)],
                           federations=federations, size_types=size_types, k=k, m=m,lk=len(k),lm=len(m))


@app.route("/add_community_reconfirm", methods=["GET", "POST"])
def add_community_reconfirm():

    feds = pd.read_csv(os.path.join(app.config["UPLOADS"], 'federations.csv'))
    federations = list(set(feds['Federation Name']))
    size_types = list(set(feds['City-Size']))

    new_record = pd.read_msgpack(session.get('new_record'))

    for index, row in new_record.iterrows():
        if row[feds.columns[0]] in list(feds[feds.columns[0]]):
            feds.drop(feds[feds[feds.columns[0]] == row[feds.columns[0]]].index, inplace=True)

    feds = feds.append(new_record)
    feds.sort_values(feds.columns[0], ascending=True, inplace=True)

    feds.to_csv(os.path.join(app.config["UPLOADS"], 'federations.csv'), index=False)
    return redirect(url_for('add_fed_file'))


@app.route("/add_fed_file3", methods=["GET", "POST"])
def add_fed_file3():
    feds = pd.read_csv(os.path.join(app.config["UPLOADS"], 'federations.csv'))

    f_data = request.form.get("federation")
    fedsize_data = request.form.get("fedsize")

    feds.loc[feds['Federation Name']==f_data, 'City-Size'] = fedsize_data


    feds.sort_values(feds.columns[0], ascending=True, inplace=True)


    feds.to_csv(os.path.join(app.config["UPLOADS"], 'federations.csv'), index=False)
    return redirect(url_for('add_fed_file'))


@app.route('/remove_record/<string:community>', methods=["GET", "POST"])
def remove_record(community):

    feds = pd.read_csv(os.path.join(app.config["UPLOADS"], 'federations.csv'))
    feds.drop(feds[feds['Community'] == community].index, inplace=True)

    feds.sort_values(feds.columns[0], ascending=True, inplace=True)

    feds.to_csv(os.path.join(app.config["UPLOADS"], 'federations.csv'), index=False)
    #feds.loc[feds['Community'] == community, 'City-Size'] = 'x'
    return redirect(url_for('add_fed_file'))




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

        if 'City-Size' in upl_file.columns:
            upl_file.drop('City-Size', axis=1, inplace=True)



        #get selected field
        merge_field = request.form.get('field')

        if ('City-Size' in columns) and (merge_field!='City-Size'):
            upl_file.drop(columns=['City-Size'], inplace=True)

        #remove dots and commas from communities
        upl_file[merge_field] = upl_file[merge_field].str.title()
        upl_file[merge_field] = upl_file[merge_field].str.replace('.','')
        upl_file[merge_field] = upl_file[merge_field].str.replace(',','')



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

            city_size_num = pd.DataFrame(report.groupby('City-Size').size().reset_index(name="counts"))

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

@app.route('/api', methods=['GET', 'POST','PUT'])
def api():
    path = session.get('file_path')

    report = pd.read_excel(path, sheet_name = 0)

    result = []

    for index, row in report.iterrows():
        result.append(row.to_dict())

    return jsonify(result[0])


@app.route('/search', methods=['GET', 'POST'])
def search():
    if request.method == "POST":

        q = request.form.get("q")
        session['q']=q

        feds = pd.read_csv(os.path.join(app.config["UPLOADS"], 'federations.csv'))
        cols = list(feds.columns)

        feds.fillna(' ', inplace=True)

        federations = list(set(feds['Federation Name']))
        size_types = list(set(feds['City-Size']))


        #y = '[{"Community": "Atlanta","City-Size": "xx","Federation Name": "testv", "Notes": "None"},{"Community": "York","City-Size": "xx","Federation Name": "testv", "Notes": "None"}]'
        #path = session.get('file_path')
        #report = pd.read_excel(path, sheet_name = 0)
        # result = {}


        for index, row in feds.iterrows():
           es.index(index="communities2", id=index, body=row.to_dict())

        #f = open(os.path.join(app.config["UPLOADS_JSON"], "test.json"))
        #f_content = f.read()

        #es.index(index="test10", body=json.loads(f_content))
        #resp = es.search(index="communities1", body={"query": {"multi_match": {"fields": ["*"], "query": {"regex": {"query": "*"+q+"*"}}}}})

        if q is None or q.strip()=="":
            return redirect(url_for('add_fed_file'))



        resp = es.search(index="communities2", body={"size":1000,"query":{"query_string": {"query": "*"+q+"*", "fields":["*"]}}})

        report = pd.DataFrame([item['_source'] for item in resp['hits']['hits']])

        if report.shape[0] == 0:
               #report = feds
            no_results = "We don't have any results for "

            return render_template("search.html", resp=resp, q=q, federations=federations, size_types=size_types, no_results=no_results)


        #except:

            #return render_template("search.html", q=q, tables=[report[cols].to_html(classes='table-sticky sticky-enabled', index=False)], federations=federations, size_types=size_types, no_results=no_results)

        results_message = "Results for "

        return render_template("search.html", q=q, tables=[report[cols].to_html(classes='table-sticky sticky-enabled', index=False)], federations=federations, size_types=size_types, results_message=results_message)

    else:

        q = session.get('q')

        feds = pd.read_csv(os.path.join(app.config["UPLOADS"], 'federations.csv'))
        cols = list(feds.columns)

        feds.fillna(' ', inplace=True)

        federations = list(set(feds['Federation Name']))
        size_types = list(set(feds['City-Size']))

        if q is None or q.strip() == "":
            return redirect(url_for('add_fed_file'))

        if q is None or q.strip() == "":
            return redirect(url_for('add_fed_file'))

        try:

            resp = es.search(index="communities1",
                             body={"query": {"query_string": {"query": "*" + q + "*", "fields": ["*"]}}})
            report = pd.DataFrame([item['_source'] for item in resp['hits']['hits']])

            if report.shape[0] == 0:
                # report = feds
                no_results = "We don't have any results for "

                return render_template("search.html", q=q, federations=federations, size_types=size_types,
                                       no_results=no_results)


        except:

            return render_template("search.html", q=q,
                                   tables=[report[cols].to_html(classes='table-sticky sticky-enabled', index=False)],
                                   federations=federations, size_types=size_types, no_results=no_results)

        results_message = "Results for "

        return render_template("search.html", q=q,
                               tables=[report[cols].to_html(classes='table-sticky sticky-enabled', index=False)],
                               federations=federations, size_types=size_types, results_message=results_message)


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


@app.route("/users")
def users():
    users = User.query.all()
    return redirect(url_for('home'))


@app.route("/uploader_fed", methods=["GET", "POST"])
#function that allows user to upload file to the system
def uploader_fed():
    if request.method == "POST":

        if request.files:

            file = request.files["file"]

            #verifies that filename is not blank
            if file.filename == '':
                    flash('No file selected or uploading')
                    return redirect('/add_fed_file')

            #verifies file type
            if not allowed_file(file.filename):
                    flash('Unsupported file type')
                    return redirect('/add_fed_file')


            fed_filename = secure_filename(file.filename)

            path = os.path.join(app.config["UPLOADS"], fed_filename)

            #saves file
            file.save(path)


            #verifies csv format
            if not check_csv(fed_filename):
                try:
                    #read excel file
                    upl_file = pd.read_excel(path, sheet_name = 0)


                except:
                    flash('Unsupported file type')
                    return redirect('/add_fed_file')

            else:
                try:
                    #read csv
                    upl_file = pd.read_csv(path)

                except:
                    flash('Unsupported file type')
                    return redirect('/add_fed_file')

            # read federations file
            feds = pd.read_csv(os.path.join(app.config["UPLOADS"], 'federations.csv'))

            if set(upl_file.columns)==set(feds.columns):
                feds=feds.append(upl_file)
                feds.to_csv(os.path.join(app.config["UPLOADS"], 'federations.csv'), index=False)

        return redirect('/add_fed_file')



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
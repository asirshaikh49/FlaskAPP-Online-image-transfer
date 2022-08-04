from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS,cross_origin
from flask import Flask, render_template,request
from flask_wtf import FlaskForm
from wtforms import FileField
from flask_uploads import configure_uploads, IMAGES, UploadSet
import os
import pathlib
import requests
from flask import session, abort, redirect
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
import google.auth.transport.requests

app=Flask(__name__)


limiter = Limiter(app,key_func=get_remote_address, default_limits=["5 per minute"])
app.config['SECRET_KEY']='thesecretkey'
app.config['UPLOADED_IMAGES_DEST'] = 'static/imges'
images = UploadSet('images', IMAGES)
configure_uploads(app, images)
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"



#google authentication start

GOOGLE_CLIENT_ID = "626021538555-lvlp15uifhpefufg97nem9vbc3g4urqs.apps.googleusercontent.com"
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")

flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri="http://127.0.0.1:5000/callback"
)

#google authentication end

#check function
def login_is_required(function):
    def wrapper(*args, **kwargs):
        if "google_id" not in session:
            return abort(401)  # Authorization required
        else:
            return function()

    return wrapper


@app.route("/", methods=['GET','POST'])
@cross_origin()
def index():
    #return "Hello World <a href='/login'><button>Login</button></a>"
    return render_template('login.html')

@app.route("/login",methods=['GET','POST'])
@cross_origin()
def login():
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)

@app.route("/callback",methods=['GET','POST'])
@cross_origin()
def callback():
    flow.fetch_token(authorization_response=request.url)

    if not session["state"] == request.args["state"]:
        abort(500)  # State does not match!
    credentials = flow.credentials
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID
    )
    session["google_id"] = id_info.get("sub")
    session["name"] = id_info.get("name")
    return redirect('/Authenticate')

@app.route("/Authenticate",methods=['GET','POST'])
@cross_origin()
@login_is_required
def protected_area():

    credentials = flow.credentials
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID
    )
    session["google_id"] = id_info.get("sub")
    session["name"] = id_info.get("name")
    return render_template('index.html', session=[session["google_id"], session["name"]])
    # return f"Hello {session['name']}! <br/> <a href='/logout'><button>Logout</button></a>"

#images upload section start

class MyForm(FlaskForm):
    image = FileField('image')


@app.route('/upload', methods=['GET', 'POST'])
@cross_origin()
def upload():
    form = MyForm()
    img_names=[]

    if form.validate_on_submit():
        filename = images.save(form.image.data)
        img_names.append(filename)
        #return f'Filename: <h2>{filename}</h2> Uploaded Succesfully <a class="btn" href="/upload">Upload</a>'
        return render_template('results.html', filename=filename)
    return render_template('upload.html', form=form)
#images upload section end


#gallery section
@app.route("/gallery",methods=['GET','POST'])
@cross_origin()
def gallery():                                       # This method is used to upload files
    # img_names=os.listdir('./static/imges')
    path = 'static/imges/'
    img_names = sorted(os.listdir(path),
                     key=lambda x: os.path.getctime(path + x))  # Sorting as per image upload date and time
    # print(uploads)
    # uploads = os.listdir('static/uploads')
    img_names = ['imges/' + file for file in img_names]
    img_names.reverse()
    return render_template('gallery.html',img_names=img_names)


#gallery section ends

@app.route("/logout",methods=['GET','POST'])
@cross_origin()
def logout():
    session.clear()
    return redirect("/")

if __name__ == '__main__':

    app.run(debug=True)
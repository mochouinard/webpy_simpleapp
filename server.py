# Sample code of a more complex webpy application: https://github.com/nopri/onlinestore-multi
import web
from web import form
import ConfigParser
import model

# This is used to simplify getting value from the python ConfigParser
def ConfigSectionMap(section):
	dict1 = {}
	options = Config.options(section)
	for option in options:
		try:
			dict1[option] = Config.get(section, option)
			if dict1[option] == -1:
				DebugPrint("skip: %s" % option)
		except:
			print("exception on %s!" % option)
			dict1[option] = None
	return dict1

# Config file stuff
Config = ConfigParser.ConfigParser()
Config.read('local.ini')

web.config.smtp_server = ConfigSectionMap("smtp")['server']
web.config.smtp_username = ConfigSectionMap("smtp")['username']
web.config.smtp_password = ConfigSectionMap("smtp")['password']
web.config.smtp_debuglevel = 99
smtp_starttls = ConfigSectionMap("smtp")['starttls']
if smtp_starttls == "true":
	web.config.smtp_starttls = True
web.config._from_email_automated = ConfigSectionMap("smtp")['from']
web.config._site_root = ConfigSectionMap("web")['root_url']

# Database initiation for the webpy engine
db = web.database(dbn='sqlite', db='sample.db')

#web.config.debug = False

# Define the different URL regex and their corresponding class
urls = ('/ticket/(.*)', 'ticket',
	'/auth/(.*)', 'auth',
	'/admin/user/(.*)', 'admin_user')

app = web.application(urls, globals())

# This is code to allow session to work while in debug mode
if web.config.get('_session') is None:
	session = web.session.Session(app, web.session.DiskStore('sessions'), initializer={'email': ""})
	web.config._session = session
else:
	session = web.config._session

# Load the webpy template engine
render = web.template.render('templates/', base='layout', globals={'session': session})

# This are Form validation value.  We define them here because we can reuse them in different forms
vpass = form.regexp(r".{3,20}$", 'must be between 3 and 20 characters')
vemail = form.regexp(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', "must be a valid email address")
vuser_exist = form.Validator('Username already exist. <a href="/auth/login">Click here</a> to get to the login screen or <a href="/auth/lost">click here</a> if you lost your password.', lambda u: u is None or model.get_user(db,u.email) is None)

vuser_notexist = form.Validator('Username doesn\'t exist.', lambda u: u is not None and model.get_user(db,u.email) is not None)
vuser_auth = form.Validator('Invalid password', lambda u: u is not None and model.auth_user(db,u.email,u.password) is not None)

vuser_verified = form.Validator('Account not validated. <a href="/auth/authkey">click here</a> to get a new validation key.', lambda u: u is not None and model.get_user(db,u.email).status == 'VERIFIED')

vuser_notverified = form.Validator('Account is not waiting to be verified', lambda u: u is not None and model.get_user(db,u.email).status == 'VERIFICATION_REQUIRED')

vuser_alreadyverified = form.Validator('Account already verified', lambda u: u is not None and model.get_user(db,u.email).status != 'VERIFIED')

# This is where we define form to be generated in HTML by webpy.  It include support for fields verifications.
# You can see vemail vpass that was define before.  If you use the web UI and try to write an email that not in the correct format, it will fail.. it done because of this

login_form = form.Form(
	form.Textbox("email", vemail, description="E-Mail"),
	form.Password("password", vpass, description="Password"),
	form.Button("submit", type="submit", description="Login"),
	validators = [
		vuser_notexist,
		vuser_auth,
		vuser_verified]
)

register_form = form.Form(
	form.Textbox("email", vemail, description="E-Mail"),
	form.Password("password", vpass, description="Password"),
	form.Password("password2", description="Repeat password"),
	form.Button("submit", type="submit", description="Register"),
	validators = [
		form.Validator("Passwords didn't match", lambda i: i.password == i.password2),
		vuser_exist]
)

authkey_form = form.Form(
	form.Textbox("email", vemail, description="E-Mail"),
	form.Button("submit", type="submit", description="Request Key"),
	validators = [
			vuser_notexist,
			vuser_alreadyverified,
			vuser_notverified]
)

class admin_user:
	def GET(self, rest):
		return "Requested data for %s" % ( rest,)
	def DELETE(self, rest):
		return "%s DELETED" % (rest)
	
# This is the main class auth that is called used by the urls value we saw before
class auth:
	# This is the type of query... We got GET POST PUT DELETE (May other, but I know of those)
	def GET(self, rest):
		if rest == 'logout':
			session.kill()
			session.email = ""
			return render.auth_logout_get()
		elif rest == 'login':
			f = login_form()
			return render.auth_login_get(f)
		elif rest == 'create':
			f = register_form()
			return render.auth_create_get(f)
		elif rest == 'authkey':
			f = authkey_form()
			i = web.input(key='')
			if i.key != "":
				res = model.check_auth_string(db,i.key)
				if res == 'ALREADY_VERIFIED':
					return render.auth_authkey_res_ALREADY_VERIFIED()
				elif res == 'VERIFIED':
					return render.auth_authkey_res_VERIFIED()
				elif res == 'KEY_INVALID':
					return render.auth_authkey_res_KEY_INVALID()
				else:
					return web.internalerror("Invalid response")
			return render.auth_authkey_get(f)

		return "TODO"
	def POST(self, rest):
		if rest == 'login':
			f = login_form()
			if not f.validates():
				return render.auth_login_get(f)
			# TODO Save User Session Authentication
			i = web.input()
			session.email = i.email
  
			raise web.seeother("/ticket/")
		elif rest == 'create':
			f = register_form()
			if not f.validates():
				return render.auth_create_get(f)

			i = web.input()
			try:	
				result = db.insert('users', email=i.email, password=i.password)
			except sqlite3.IntegrityError as err:
				# THIS SHOULD NOT HAPPEN, but just in case : column email is not unique
				return err

			model.send_auth_string(db,i.email)
			return render.auth_create_post()
		elif rest == 'authkey':
			f = authkey_form()
			if not f.validates():
				return render.auth_authkey_get(f)

			i = web.input()
			model.send_auth_string(db,i.email)
			return render.auth_authkey_post(i.email)
			

			
# A just a place holder for a ticket system, doesn't do much
class ticket:
	def GET(self, name):
		web.header('Access-Control-Allow-Origin', '*')

		tickets = db.select('tickets')
		return render.index_get(tickets)
	def POST(self, name=None):
		i = web.input()
		id = db.insert("tickets", title=i.title)

		return render.index(id)
		#return "ADDED %s" % (name,)
	def OPTIONS(Self, name=None):
		web.header('Access-Control-Allow-Origin', '*')
		web.header('Access-Control-Allow-Headers', '*')
		web.header('Access-Control-Max-Age', '1728000')
		web.header('Access-Control-Allow-Methods', 'POST, GET, DELETE, PUT, OPTIONS')
		web.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept')
		return ""

class static:
	def GET(self,name):
		ext = name.split(".")[-1] # Gather extension

		cType = {
				"png":"images/png",
				"jpg":"images/jpeg",
				"gif":"images/gif",
				"ico":"images/x-icon"  
		}

		if name in os.listdir('static'):  # Security
				if cType[ext]:
					web.header("Content-Type", cType[ext]) # Set the Header
				return open('static/%s'%name,"rb").read() # Notice 'rb' for reading images
		else:
				raise web.notfound()

if __name__ == "__main__":
	app.run()


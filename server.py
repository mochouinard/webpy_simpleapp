import web
from web import form
import ConfigParser

#res = model.check_auth_string(db,i.key)
# Sample code https://github.com/nopri/onlinestore-multi
import model

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

Config = ConfigParser.ConfigParser()
Config.read('local.ini')


urls = ('/ticket/(.*)', 'ticket',
	'/auth/(.*)', 'auth')

web.config.smtp_server = ConfigSectionMap("smtp")['server']
web.config.smtp_username = ConfigSectionMap("smtp")['username']
web.config.smtp_password = ConfigSectionMap("smtp")['password']
web.config._from_email_automated = ConfigSectionMap("smtp")['from']

web.config._site_root = ConfigSectionMap("web")['root_url']

db = web.database(dbn='sqlite', db='sample.db')

#web.config.debug = False

app = web.application(urls, globals())
if web.config.get('_session') is None:
        session = web.session.Session(app, web.session.DiskStore('sessions'), initializer={'email': ""})
        web.config._session = session
else:
        session = web.config._session

render = web.template.render('templates/', base='layout', globals={'session': session})


vpass = form.regexp(r".{3,20}$", 'must be between 3 and 20 characters')
vemail = form.regexp(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', "must be a valid email address")
vuser_exist = form.Validator('Username already exist. <a href="/auth/login">Click here</a> to get to the login screen or <a href="/auth/lost">click here</a> if you lost your password.', lambda u: u is None or model.get_user(db,u.email) is None)

vuser_notexist = form.Validator('Username doesn\'t exist.', lambda u: u is not None and model.get_user(db,u.email) is not None)
vuser_auth = form.Validator('Invalid password', lambda u: u is not None and model.auth_user(db,u.email,u.password) is not None)

vuser_verified = form.Validator('Account not validated TODO Link to get a new auth key', lambda u: u is not None and model.get_user(db,u.email).status == 'VERIFIED')

vuser_notverified = form.Validator('Account is not waiting to be verified', lambda u: u is not None and model.get_user(db,u.email).status == 'VERIFICATION_REQUIRED')

vuser_alreadyverified = form.Validator('Account already verified', lambda u: u is not None and model.get_user(db,u.email).status != 'VERIFIED')

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


class auth:
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
			return render.auth_create_get(f,"")
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
				note = f.note
				f.note = ""
				return render.auth_create_get(f,note)

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
			

			

class ticket:
    def GET(self, name):
	tickets = db.select('tickets')
	return render.index_get(tickets)
    def POST(self, name=None):
	i = web.input()
	id = db.insert("tickets", title=i.title)

	return render.index(id)
	#return "ADDED %s" % (name,)


if __name__ == "__main__":
	app.run()


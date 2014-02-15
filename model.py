import string
import random
import web

#db = web.database(dbn='sqlite', db='ticket.db')

def id_generator(size=6, chars=string.ascii_uppercase + string.digits):
	return ''.join(random.choice(chars) for x in range(size))

def send_auth_string(db,email):
	hash = id_generator(32, chars=string.ascii_uppercase + string.digits + string.ascii_lowercase)
	db.insert('auth_tokens', email=email, key=hash)
	web.sendmail(web.config._from_email_automated, email, 'Confirm your email', '%s/auth/authkey?key=%s' % (web.config._site_root,hash,) )

def check_auth_string(db,key):
	try:
		res = db.select('auth_tokens', where="key=$key AND ts_created > date('now', '-1 day')", vars=locals())
		mod = db.update('users', where='email=$email AND status=$var', vars={'email':res[0].email,'var':'VERIFICATION_REQUIRED'}, status='VERIFIED')
		if mod == 0:
			return "ALREADY_VERIFIED"
		return "VERIFIED"
	except IndexError:
		return "KEY_NOTFOUND"

def get_user(db,email):
	try:
		return db.select('users', where='email=$email', vars=locals())[0]
	except IndexError:
		return None

def auth_user(db,email, password):
        try:
                return db.select('users', where='email=$email and password=$password', vars=locals())[0]
        except IndexError:
                return None


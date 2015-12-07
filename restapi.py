import falcon
import json
import webbrowser
import random
import string
import sqlite3
from passlib.hash import md5_crypt

api = application = falcon.API()

db = sqlite3.connect(':memory:')
cursor = db.cursor()
cursor.execute('''
	CREATE TABLE users(id INTEGER PRIMARY KEY, username TEXT, password TEXT, 
	info TEXT, sessiontoken TEXT)''')
db.commit()


class SetEncoder(json.JSONEncoder):
	def default(self, obj):
		if isinstance(obj, set):
			return list(obj)
		return json.JSONEncoder.default(self, obj)


class UserResource(object):
	# Returns user info
	def on_get(self, req, resp):
		cookies = req.cookies
		if 'sessiontoken' in cookies:
			cookieValue = cookies['sessiontoken']
			cursor.execute('''SELECT info FROM users where sessiontoken = ?''', [cookieValue])
			row = cursor.fetchone()
			if (row == None):
				doc = { 'Please sign in' }
			else:
				doc = { row }
		else: doc = { 'no cookie value' }
		resp.body = json.dumps(doc, cls=SetEncoder)


	# Add User
	def on_post(self, req, resp):
		username = req.get_param('username')
		password = req.get_param('password')
		
		info = req.get_param('info')

		if (username == None or password == None):
			doc = {
				'You did not enter a valid username and password please try again'
			}
		else:
			passhash = md5_crypt.encrypt(password)
			cursor.execute('''INSERT INTO users(username, password, info, sessiontoken)
				VALUES(?,?,?,'')''', (username, passhash, info))
 			db.commit()
			doc = { 'Updated' }
		resp.body = json.dumps(doc, cls=SetEncoder)
		webbrowser.open('signon.html')

class UserPutResource(object):
	# Updates info 
	def on_post(self, req, resp):
		newinfo = req.get_param('info')
		cookies = req.cookies
		if 'sessiontoken' in cookies:
			cookieValue = cookies['sessiontoken']
			cursor.execute('''SELECT info FROM users WHERE sessiontoken = ?''', [cookieValue])
			row = cursor.fetchone()
			if (row == None):
				doc = { 'Please sign in' }
			else:
				cursor.execute('''UPDATE users SET info = ? WHERE sessiontoken = ?''', 
					(newinfo, cookieValue))
				db.commit()
				doc = { 'Updated info' }
		else: doc = { 'no cookie value' }
		resp.body = json.dumps(doc, cls=SetEncoder)

class UserDeleteResource(object):
	# Deletes user
	def on_get(self, req, resp):
		cookies = req.cookies
		if 'sessiontoken' in cookies:
			cookieValue = cookies['sessiontoken']
			cursor.execute('''SELECT * FROM users WHERE sessiontoken = ?''', [cookieValue])
			row = cursor.fetchone()
			if (row == None):
				doc = { 'Please sign in' }
			else: 
				cursor.execute('''DELETE FROM users WHERE sessiontoken = ?''', [cookieValue])
				db.commit()
				resp.unset_cookie('sessiontoken')
				doc = { 'Deleted user' }
		else: doc = { 'no cookie value' }
		resp.body = json.dumps(doc, cls=SetEncoder)

class AuthResource(object):
	# Gets Session Token
	def on_post(self, req, resp):
		username = req.get_param('username')
		password = req.get_param('password')

		if (username == None or password == None):
			doc = { 'Please try again' }
		else:
			cursor.execute('''SELECT password FROM users WHERE username = ?''', [username])
			row = cursor.fetchone()
			if (row == None):
				doc = { 'Invalid username and password' }
			else:
				if (md5_crypt.verify(password, row[0])):
					cookie = ''.join(random.SystemRandom().choice(string.ascii_uppercase + 
						string.digits) for _ in range(6))
					resp.set_cookie('sessiontoken', cookie, domain='.localhost', secure = False)
					cursor.execute('''UPDATE users SET sessiontoken = ? WHERE username = ?''', 
						(cookie, username))
					db.commit()
					doc = { 'Session Started' }
				else: doc = { 'Wrong Password' }
		resp.body = json.dumps(doc, cls=SetEncoder)
		webbrowser.open('info.html')

class AuthDeleteResource(object):
	# Delete Session Token
	def on_get(self, req, resp):
		cookies = req.cookies
		if 'sessiontoken' in cookies:
			cookieValue = cookies['sessiontoken']
			cursor.execute('''UPDATE users SET sessiontoken = Null WHERE sessiontoken = ?''',
				[cookieValue])
			db.commit()
			resp.unset_cookie('sessiontoken')
			doc = { 'Unset Token' }
		else: doc = { 'no cookie value' }
		resp.body = json.dumps(doc, cls=SetEncoder)

class Resource(object):
	# Returns Hello World
	def on_get(self, req, resp):
		cookies = req.cookies
		if 'sessiontoken' in cookies:
			cookieValue = cookies['sessiontoken']
			cursor.execute('''SELECT info FROM users WHERE sessiontoken = ?''',[cookieValue])
			row = cursor.fetchone()
			if (row == None): doc = { 'Hello World!' }
			else: doc = { 'Hello World!' : row }
		else: doc = { 'Hello World!' }
		resp.body = json.dumps(doc, cls=SetEncoder)

api.add_route('/', Resource())
api.add_route('/user',UserResource())
api.add_route('/user/delete',UserDeleteResource())
api.add_route('/user/put',UserPutResource())
api.add_route('/auth',AuthResource())
api.add_route('/auth/delete',AuthDeleteResource())


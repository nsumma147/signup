#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import webapp2
import cgi
import re

signup_form = """
<form method="post" action="/">
<h1>Signup</h1>
<h3>Username<h3>
<input type="text" name ="username" value ="%(username)s"/>
<span type="color:red">%(username_error)s</span>
<br>
<h3>Password</h3>
<input type="text" name ="password" value=""/>
<span type="color:red">%(password_error)s</span>
<br>
<h3>Verify Password</h3>
<input type="text" name ="ver_password" value=""/>
<span type="color:red">%(ver_password_error)s</span>
<br>
<h3>Email(optional)</h3>
<input type="text" name = "email" value="%(email)s"/>
<span type="color:red">%(email_error)s</span>
<br>
<input type="submit" value="Submit"/>
"""

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return PASS_RE.match(password)

EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return EMAIL_RE.match(email)



class MainHandler(webapp2.RequestHandler):
    def write_form(self, username_error="", password_error="",ver_password_error="",
        email_error="", username="", password="",email=""):
            self.response.out.write(signup_form % {
            "username_error":username_error,
            "password_error":password_error,
            "ver_password_error":ver_password_error,
            "email_error":email_error,
            "username":username,
            "password":password,
            "email":email
            })

    def get(self):
        self.write_form()

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        ver_password = self.request.get('ver_password')
        email = self.request.get('email')
        password_error = ""
        email_error = ""
        ver_password_error = ""
        username_error = ""
        error = False

        if not valid_username(username):
            username_error = "This is not a valid username"
            error = True

        if not valid_password(password):
            password_error= "This is not a valid password"
            error = True

        if ver_password != password:
            ver_password_error = "The passwords do not match"
            error = True

        if not valid_email(email):
            email_error = "This is not a valid email"
            error = True

        if error:
            self.write_form(username_error = username_error, password_error=password_error,
            ver_password_error=ver_password_error,email_error=email_error,username=username,
            password=password, email = email)
        else:    
            self.response.out.write("Thanks!")

app = webapp2.WSGIApplication([
    ('/', MainHandler)
], debug=True)

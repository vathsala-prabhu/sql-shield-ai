from predict import predict_query

samples = [
    "' UNION SELECT username, password FROM users --",
    "' union select username, password from users --",
    "' union select username , password from users --",
    "' union  select  username  ,  password  from  users  --",
    "SELECT name FROM users WHERE id = 5",
    "select name from users where id = 5",
    "select name from users where id  =  5",
]

for s in samples:
    print(s, "->", predict_query(s))
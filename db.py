import mysql.connector

conn = mysql.connector.connect(user='root', password = 'root', host = '127.0.0.1', database = 'kibbutz');

selectQuery = 'select id, name from users'

cursor = conn.cursor();

cursor.execute(selectQuery)
for (id, name) in cursor:
    print("{}, {}".format(id, name))

cursor.close()
conn.close()
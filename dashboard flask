from flask import Flask
import sqlite3

DB = "/opt/edr-agent/edr.db"
app = Flask(__name__)

@app.route("/")
def home():
    conn = sqlite3.connect(DB)
    c = conn.cursor()

    c.execute("SELECT COUNT(*) FROM events")
    total = c.fetchone()[0]

    c.execute("SELECT level, COUNT(*) FROM events GROUP BY level")
    levels = c.fetchall()

    c.execute("""
    SELECT timestamp, level, event_type, ip, message
    FROM events ORDER BY id DESC LIMIT 30
    """)
    events = c.fetchall()

    conn.close()

    html = "<h1>EDR Dashboard</h1>"
    html += f"<p>Total: {total}</p>"

    for lvl,count in levels:
        html += f"<p>{lvl}: {count}</p>"

    html += "<hr><table border=1>"
    for e in events:
        html += f"<tr><td>{e}</td></tr>"

    html += "</table>"
    return html

app.run(host="0.0.0.0", port=5000)

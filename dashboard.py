from flask import Flask
import sqlite3

DB_PATH = "/opt/edr-agent/edr.db"

app = Flask(__name__)


def get_db():
    return sqlite3.connect(DB_PATH)


@app.route("/")
def home():
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM events")
    total_events = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM events WHERE level = 'LOW'")
    low_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM events WHERE level = 'MEDIUM'")
    medium_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM events WHERE level = 'HIGH'")
    high_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM events WHERE event_type = 'IP_BLOCK'")
    blocked_count = cursor.fetchone()[0]

    cursor.execute("""
        SELECT ip, COUNT(*) as total
        FROM events
        WHERE ip IS NOT NULL AND ip != ''
        GROUP BY ip
        ORDER BY total DESC
        LIMIT 5
    """)
    top_ips = cursor.fetchall()

    cursor.execute("""
        SELECT timestamp, level, event_type, ip, message
        FROM events
        ORDER BY id DESC
        LIMIT 30
    """)
    events = cursor.fetchall()

    conn.close()

    html = f"""
    <!DOCTYPE html>
    <html lang="pt-br">
    <head>
        <meta charset="UTF-8">
        <title>Linux EDR Dashboard</title>
        <meta http-equiv="refresh" content="10">

        <style>
            * {{
                box-sizing: border-box;
            }}

            body {{
                margin: 0;
                font-family: Arial, Helvetica, sans-serif;
                background: #0f172a;
                color: #e5e7eb;
            }}

            .container {{
                padding: 30px;
            }}

            .header {{
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 30px;
            }}

            .title h1 {{
                margin: 0;
                color: #38bdf8;
                font-size: 32px;
            }}

            .title p {{
                margin: 5px 0 0;
                color: #94a3b8;
            }}

            .status {{
                background: #064e3b;
                color: #a7f3d0;
                padding: 10px 18px;
                border-radius: 999px;
                font-weight: bold;
                box-shadow: 0 0 20px rgba(16, 185, 129, 0.25);
            }}

            .cards {{
                display: grid;
                grid-template-columns: repeat(5, 1fr);
                gap: 18px;
                margin-bottom: 30px;
            }}

            .card {{
                background: #111827;
                border: 1px solid #1f2937;
                border-radius: 16px;
                padding: 20px;
                box-shadow: 0 10px 25px rgba(0,0,0,0.25);
            }}

            .card h3 {{
                margin: 0 0 10px;
                color: #94a3b8;
                font-size: 14px;
                text-transform: uppercase;
                letter-spacing: 1px;
            }}

            .card .number {{
                font-size: 34px;
                font-weight: bold;
            }}

            .low {{ color: #22c55e; }}
            .medium {{ color: #facc15; }}
            .high {{ color: #ef4444; }}
            .blocked {{ color: #fb7185; }}
            .total {{ color: #38bdf8; }}

            .grid {{
                display: grid;
                grid-template-columns: 1fr 2fr;
                gap: 20px;
            }}

            .panel {{
                background: #111827;
                border: 1px solid #1f2937;
                border-radius: 16px;
                padding: 20px;
                box-shadow: 0 10px 25px rgba(0,0,0,0.25);
            }}

            .panel h2 {{
                margin-top: 0;
                color: #e5e7eb;
                font-size: 20px;
            }}

            table {{
                width: 100%;
                border-collapse: collapse;
                font-size: 14px;
            }}

            th {{
                text-align: left;
                color: #94a3b8;
                font-weight: normal;
                padding: 12px;
                border-bottom: 1px solid #334155;
            }}

            td {{
                padding: 12px;
                border-bottom: 1px solid #1f2937;
                color: #e5e7eb;
            }}

            tr:hover {{
                background: #1e293b;
            }}

            .badge {{
                padding: 5px 10px;
                border-radius: 999px;
                font-size: 12px;
                font-weight: bold;
            }}

            .badge-low {{
                background: rgba(34,197,94,0.15);
                color: #22c55e;
            }}

            .badge-medium {{
                background: rgba(250,204,21,0.15);
                color: #facc15;
            }}

            .badge-high {{
                background: rgba(239,68,68,0.15);
                color: #ef4444;
            }}

            .event-type {{
                color: #38bdf8;
                font-weight: bold;
            }}

            .ip-list {{
                list-style: none;
                padding: 0;
                margin: 0;
            }}

            .ip-list li {{
                display: flex;
                justify-content: space-between;
                padding: 12px;
                margin-bottom: 10px;
                background: #0f172a;
                border-radius: 10px;
                border: 1px solid #1f2937;
            }}

            .footer {{
                margin-top: 25px;
                color: #64748b;
                font-size: 13px;
                text-align: center;
            }}

            @media (max-width: 1000px) {{
                .cards {{
                    grid-template-columns: repeat(2, 1fr);
                }}

                .grid {{
                    grid-template-columns: 1fr;
                }}
            }}
        </style>
    </head>

    <body>
        <div class="container">

            <div class="header">
                <div class="title">
                    <h1>Linux EDR Dashboard</h1>
                    <p>Monitoramento de eventos, risco e resposta ativa</p>
                </div>
                <div class="status">AGENTE ATIVO</div>
            </div>

            <div class="cards">
                <div class="card">
                    <h3>Total de Eventos</h3>
                    <div class="number total">{total_events}</div>
                </div>

                <div class="card">
                    <h3>Baixo Risco</h3>
                    <div class="number low">{low_count}</div>
                </div>

                <div class="card">
                    <h3>Médio Risco</h3>
                    <div class="number medium">{medium_count}</div>
                </div>

                <div class="card">
                    <h3>Alto Risco</h3>
                    <div class="number high">{high_count}</div>
                </div>

                <div class="card">
                    <h3>IPs Bloqueados</h3>
                    <div class="number blocked">{blocked_count}</div>
                </div>
            </div>

            <div class="grid">
                <div class="panel">
                    <h2>Top IPs</h2>
                    <ul class="ip-list">
    """

    if top_ips:
        for ip, total in top_ips:
            html += f"""
                        <li>
                            <span>{ip}</span>
                            <strong>{total}</strong>
                        </li>
            """
    else:
        html += """
                        <li>
                            <span>Nenhum IP registrado</span>
                            <strong>0</strong>
                        </li>
        """

    html += """
                    </ul>
                </div>

                <div class="panel">
                    <h2>Últimos Eventos</h2>
                    <table>
                        <tr>
                            <th>Data</th>
                            <th>Nível</th>
                            <th>Tipo</th>
                            <th>IP</th>
                            <th>Mensagem</th>
                        </tr>
    """

    for timestamp, level, event_type, ip, message in events:
        level_class = level.lower()

        badge_class = "badge-low"
        if level == "MEDIUM":
            badge_class = "badge-medium"
        elif level == "HIGH":
            badge_class = "badge-high"

        html += f"""
                        <tr>
                            <td>{timestamp}</td>
                            <td><span class="badge {badge_class}">{level}</span></td>
                            <td class="event-type">{event_type}</td>
                            <td>{ip if ip else "-"}</td>
                            <td>{message}</td>
                        </tr>
        """

    html += """
                    </table>
                </div>
            </div>

            <div class="footer">
                Atualização automática a cada 10 segundos • Linux EDR Agent
            </div>

        </div>
    </body>
    </html>
    """

    return html


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

import sqlite3

def conectar():
    conexao = sqlite3.connect("gestao_escolar.db")
    conexao.row_factory = sqlite3.Row
    return conexao


def criar_tabelas():

    conexao = conectar()
    cursor = conexao.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT NOT NULL,
            email TEXT NOT NULL,
            senha TEXT,
            tipo TEXT NOT NULL,
            telefone TEXT,
            turma TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS turmas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT NOT NULL,
            ano INTEGER NOT NULL,
            turno TEXT NOT NULL,
            curso TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS avisos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            titulo TEXT NOT NULL,
            mensagem TEXT NOT NULL,
            data TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS mensagens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            remetente_id INTEGER NOT NULL,
            destinatario_id INTEGER NOT NULL,
            mensagem TEXT NOT NULL,
            data TEXT NOT NULL,
            lida INTEGER DEFAULT 0,
            FOREIGN KEY (remetente_id) REFERENCES usuarios(id),
            FOREIGN KEY (destinatario_id) REFERENCES usuarios(id)
        )
    """)

    conexao.commit()
    conexao.close()


def criar_usuario_gestao():

    conexao = conectar()
    cursor = conexao.cursor()

    usuario = cursor.execute(
        "SELECT id FROM usuarios WHERE email = ?",
        ("admin@ete.com",)
    ).fetchone()

    if usuario is None:

        cursor.execute("""
            INSERT INTO usuarios
            (nome, email, senha, tipo, telefone, turma)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            "Administrador",
            "admin@ete.com",
            "123456",
            "gestao",
            "",
            ""
        ))

        conexao.commit()

    conexao.close()


def inicializar_banco():

    criar_tabelas()
    criar_usuario_gestao()


if __name__ == "__main__":

    inicializar_banco()

    print("Banco de dados configurado com sucesso!")
    print("Usuario: admin@ete.com")
    print("Senha: 123456")
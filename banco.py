import sqlite3
from werkzeug.security import generate_password_hash


def conectar():

    conexao = sqlite3.connect("gestao_escolar.db")
    conexao.row_factory = sqlite3.Row

    return conexao


# =========================================
# CRIAR TABELAS
# =========================================

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
            turma TEXT,
            primeiro_acesso INTEGER DEFAULT 0
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
            data TEXT NOT NULL,
            destino TEXT DEFAULT 'todos',
            turma TEXT
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

    # =========================================
    # ATUALIZAR BANCO EXISTENTE
    # =========================================

    # -----------------------------------------
    # VERIFICAR COLUNAS DE USUÁRIOS
    # -----------------------------------------

    colunas = cursor.execute(
        "PRAGMA table_info(usuarios)"
    ).fetchall()

    nomes_colunas = [
        coluna["name"]
        for coluna in colunas
    ]

    if "primeiro_acesso" not in nomes_colunas:

        cursor.execute("""
            ALTER TABLE usuarios
            ADD COLUMN primeiro_acesso INTEGER DEFAULT 0
        """)

        conexao.commit()

    # -----------------------------------------
    # VERIFICAR COLUNAS DE AVISOS
    # -----------------------------------------

    colunas_avisos = cursor.execute(
        "PRAGMA table_info(avisos)"
    ).fetchall()

    nomes_colunas_avisos = [
        coluna["name"]
        for coluna in colunas_avisos
    ]

    # -----------------------------------------
    # ADICIONAR DESTINO
    # -----------------------------------------

    if "destino" not in nomes_colunas_avisos:

        cursor.execute("""
            ALTER TABLE avisos
            ADD COLUMN destino TEXT DEFAULT 'todos'
        """)

        conexao.commit()

    # -----------------------------------------
    # ADICIONAR TURMA
    # -----------------------------------------

    if "turma" not in nomes_colunas_avisos:

        cursor.execute("""
            ALTER TABLE avisos
            ADD COLUMN turma TEXT
        """)

        conexao.commit()

    # -----------------------------------------
    # CORRIGIR AVISOS ANTIGOS
    # -----------------------------------------

    cursor.execute("""
        UPDATE avisos
        SET destino = 'todos'
        WHERE destino IS NULL
        OR destino = ''
    """)

    conexao.commit()

    conexao.close()


# =========================================
# CRIAR USUÁRIO GESTÃO
# =========================================

def criar_usuario_gestao():

    conexao = conectar()
    cursor = conexao.cursor()

    usuario = cursor.execute(
        """
        SELECT id, senha
        FROM usuarios
        WHERE email = ?
        """,
        ("admin@ete.com",)
    ).fetchone()

    if usuario is None:

        senha_hash = generate_password_hash("123456")

        cursor.execute("""
            INSERT INTO usuarios
            (
                nome,
                email,
                senha,
                tipo,
                telefone,
                turma,
                primeiro_acesso
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            "Administrador",
            "admin@ete.com",
            senha_hash,
            "gestao",
            "",
            "",
            0
        ))

        conexao.commit()

    else:

        # Corrige o administrador antigo caso
        # ele ainda esteja com senha sem hash.

        senha_atual = usuario["senha"]

        if senha_atual == "123456":

            senha_hash = generate_password_hash("123456")

            cursor.execute(
                """
                UPDATE usuarios
                SET senha = ?
                WHERE id = ?
                """,
                (
                    senha_hash,
                    usuario["id"]
                )
            )

            conexao.commit()

    conexao.close()


# =========================================
# INICIALIZAR BANCO
# =========================================

def inicializar_banco():

    criar_tabelas()
    criar_usuario_gestao()


# =========================================
# EXECUTAR
# =========================================

if __name__ == "__main__":

    inicializar_banco()

    print("Banco de dados configurado com sucesso!")
    print("Usuario: admin@ete.com")
    print("Senha inicial: 123456")
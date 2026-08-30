from banco import conectar
from werkzeug.security import generate_password_hash


conexao = conectar()

usuarios = conexao.execute(
    "SELECT id, senha FROM usuarios"
).fetchall()

for usuario in usuarios:

    senha_atual = usuario["senha"]

    # Só transforma senhas que ainda estão em texto normal
    if not senha_atual.startswith(("scrypt:", "pbkdf2:")):

        senha_hash = generate_password_hash(senha_atual)

        conexao.execute(
            """
            UPDATE usuarios
            SET senha = ?
            WHERE id = ?
            """,
            (senha_hash, usuario["id"])
        )

conexao.commit()
conexao.close()

print("Senhas atualizadas com sucesso!")
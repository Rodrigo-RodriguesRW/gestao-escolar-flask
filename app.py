from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from banco import conectar
from datetime import datetime
import secrets
import string


app = Flask(__name__)


# =========================================
# CONFIGURAÇÃO DA SESSÃO
# =========================================

app.secret_key = "ete-ariano-suassuna-gestao-escolar"


# =========================================
# GERAR SENHA INICIAL
# =========================================

def gerar_senha_inicial():

    caracteres = string.ascii_letters + string.digits

    return "".join(
        secrets.choice(caracteres)
        for _ in range(8)
    )


# =========================================
# LOGIN
# =========================================

@app.route("/", methods=["GET", "POST"])
def inicio():

    if request.method == "POST":

        email = request.form["email"].strip()
        senha = request.form["senha"].strip()

        conexao = conectar()

        usuario = conexao.execute(
            """
            SELECT *
            FROM usuarios
            WHERE email = ?
            """,
            (email,)
        ).fetchone()

        conexao.close()

        if usuario and check_password_hash(usuario["senha"], senha):

            session["usuario_id"] = usuario["id"]
            session["usuario_nome"] = usuario["nome"]
            session["usuario_email"] = usuario["email"]
            session["usuario_tipo"] = usuario["tipo"]

            # =========================================
            # PRIMEIRO ACESSO
            # =========================================

            if usuario["primeiro_acesso"] == 1:

                return redirect(
                    url_for("trocar_senha")
                )

            # =========================================
            # REDIRECIONAMENTO POR TIPO
            # =========================================

            if usuario["tipo"] == "gestao":

                return redirect(
                    url_for("dashboard")
                )

            if usuario["tipo"] == "professor":

                return redirect(
                    url_for("professor")
                )

            if usuario["tipo"] == "aluno":

                return redirect(
                    url_for("aluno")
                )

            return redirect(
                url_for("dashboard")
            )

        flash(
            "E-mail ou senha inválidos.",
            "error"
        )

    return render_template(
        "login.html"
    )


# =========================================
# PRIMEIRO ACESSO — TROCAR SENHA
# =========================================

@app.route("/trocar-senha", methods=["GET", "POST"])
def trocar_senha():

    if "usuario_id" not in session:

        return redirect(
            url_for("inicio")
        )

    conexao = conectar()

    usuario_id = session["usuario_id"]

    usuario = conexao.execute(
        """
        SELECT *
        FROM usuarios
        WHERE id = ?
        """,
        (usuario_id,)
    ).fetchone()

    if usuario is None:

        conexao.close()

        session.clear()

        flash(
            "Usuário não encontrado.",
            "error"
        )

        return redirect(
            url_for("inicio")
        )

    # =========================================
    # SE JÁ TROCOU A SENHA
    # =========================================

    if usuario["primeiro_acesso"] == 0:

        conexao.close()

        if usuario["tipo"] == "gestao":

            return redirect(
                url_for("dashboard")
            )

        if usuario["tipo"] == "professor":

            return redirect(
                url_for("professor")
            )

        if usuario["tipo"] == "aluno":

            return redirect(
                url_for("aluno")
            )

        return redirect(
            url_for("dashboard")
        )

    # =========================================
    # PROCESSAR NOVA SENHA
    # =========================================

    if request.method == "POST":

        nova_senha = request.form.get(
            "nova_senha",
            ""
        ).strip()

        confirmar_senha = request.form.get(
            "confirmar_senha",
            ""
        ).strip()

        # =========================================
        # CAMPOS VAZIOS
        # =========================================

        if not nova_senha or not confirmar_senha:

            conexao.close()

            flash(
                "Preencha os dois campos de senha.",
                "error"
            )

            return render_template(
                "trocar_senha.html",
                usuario_nome=session["usuario_nome"],
                usuario_tipo=session["usuario_tipo"]
            )

        # =========================================
        # SENHAS DIFERENTES
        # =========================================

        if nova_senha != confirmar_senha:

            conexao.close()

            flash(
                "As senhas não são iguais.",
                "error"
            )

            return render_template(
                "trocar_senha.html",
                usuario_nome=session["usuario_nome"],
                usuario_tipo=session["usuario_tipo"]
            )

        # =========================================
        # TAMANHO DA SENHA
        # =========================================

        if len(nova_senha) < 6:

            conexao.close()

            flash(
                "A nova senha deve possuir pelo menos 6 caracteres.",
                "error"
            )

            return render_template(
                "trocar_senha.html",
                usuario_nome=session["usuario_nome"],
                usuario_tipo=session["usuario_tipo"]
            )

        # =========================================
        # GERAR HASH
        # =========================================

        senha_hash = generate_password_hash(
            nova_senha
        )

        try:

            conexao.execute(
                """
                UPDATE usuarios
                SET
                    senha = ?,
                    primeiro_acesso = 0
                WHERE id = ?
                """,
                (
                    senha_hash,
                    usuario_id
                )
            )

            conexao.commit()

            conexao.close()

            flash(
                "Senha criada com sucesso!",
                "success"
            )

            # =========================================
            # REDIRECIONAMENTO
            # =========================================

            if session["usuario_tipo"] == "gestao":

                return redirect(
                    url_for("dashboard")
                )

            if session["usuario_tipo"] == "professor":

                return redirect(
                    url_for("professor")
                )

            if session["usuario_tipo"] == "aluno":

                return redirect(
                    url_for("aluno")
                )

            return redirect(
                url_for("dashboard")
            )

        except Exception as erro:

            conexao.rollback()

            print(
                "Erro ao alterar senha:",
                erro
            )

            conexao.close()

            flash(
                "Erro ao criar a nova senha.",
                "error"
            )

    conexao.close()

    return render_template(
        "trocar_senha.html",
        usuario_nome=session["usuario_nome"],
        usuario_tipo=session["usuario_tipo"]
    )


# =========================================
# DASHBOARD DA GESTÃO
# =========================================

@app.route("/dashboard")
def dashboard():

    if "usuario_id" not in session:

        return redirect(
            url_for("inicio")
        )

    if session.get("usuario_tipo") != "gestao":

        flash(
            "Você não tem permissão para acessar o painel da gestão.",
            "error"
        )

        return redirect(
            url_for("inicio")
        )

    conexao = conectar()

    total_usuarios = conexao.execute(
        """
        SELECT COUNT(*)
        FROM usuarios
        """
    ).fetchone()[0]

    total_turmas = conexao.execute(
        """
        SELECT COUNT(*)
        FROM turmas
        """
    ).fetchone()[0]

    total_alunos = conexao.execute(
        """
        SELECT COUNT(*)
        FROM usuarios
        WHERE tipo = 'aluno'
        """
    ).fetchone()[0]

    total_professores = conexao.execute(
        """
        SELECT COUNT(*)
        FROM usuarios
        WHERE tipo = 'professor'
        """
    ).fetchone()[0]

    total_avisos = conexao.execute(
        """
        SELECT COUNT(*)
        FROM avisos
        """
    ).fetchone()[0]

    conexao.close()

    return render_template(
        "dashboard.html",
        total_usuarios=total_usuarios,
        total_turmas=total_turmas,
        total_alunos=total_alunos,
        total_professores=total_professores,
        total_avisos=total_avisos,
        usuario_nome=session["usuario_nome"],
        usuario_tipo=session["usuario_tipo"]
    )


# =========================================
# USUÁRIOS
# =========================================

@app.route("/usuarios", methods=["GET", "POST"])
def usuarios_page():

    if "usuario_id" not in session:

        return redirect(
            url_for("inicio")
        )

    if session.get("usuario_tipo") != "gestao":

        flash(
            "Você não tem permissão para acessar esta área.",
            "error"
        )

        return redirect(
            url_for("dashboard")
        )

    conexao = conectar()

    if request.method == "POST":

        nome = request.form["nome"].strip()
        email = request.form["email"].strip()
        tipo = request.form["tipo"]

        telefone = request.form.get(
            "telefone",
            ""
        ).strip()

        turma = request.form.get(
            "turma",
            ""
        ).strip()

        senha_inicial = gerar_senha_inicial()

        senha = generate_password_hash(
            senha_inicial
        )

        try:

            usuario_existente = conexao.execute(
                """
                SELECT id
                FROM usuarios
                WHERE email = ?
                """,
                (email,)
            ).fetchone()

            if usuario_existente:

                flash(
                    "Erro: já existe um usuário cadastrado com este e-mail.",
                    "error"
                )

            else:

                conexao.execute(
                    """
                    INSERT INTO usuarios
                    (
                        nome,
                        email,
                        tipo,
                        telefone,
                        turma,
                        senha,
                        primeiro_acesso
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        nome,
                        email,
                        tipo,
                        telefone,
                        turma,
                        senha,
                        1
                    )
                )

                conexao.commit()

                flash(
                    f"Usuário {nome} cadastrado com sucesso! "
                    f"Senha inicial: {senha_inicial}. "
                    f"Entregue esta senha ao usuário.",
                    "success"
                )

        except Exception as erro:

            conexao.rollback()

            print(
                "Erro ao cadastrar usuário:",
                erro
            )

            flash(
                "Erro ao cadastrar usuário. Verifique os dados.",
                "error"
            )

    usuarios = conexao.execute(
        """
        SELECT *
        FROM usuarios
        ORDER BY id DESC
        """
    ).fetchall()

    turmas = conexao.execute(
        """
        SELECT *
        FROM turmas
        ORDER BY nome
        """
    ).fetchall()

    conexao.close()

    return render_template(
        "usuarios.html",
        usuarios=usuarios,
        turmas=turmas,
        usuario_nome=session["usuario_nome"],
        usuario_tipo=session["usuario_tipo"]
    )


# =========================================
# EDITAR USUÁRIO
# =========================================

@app.route("/usuarios/editar/<int:id>", methods=["GET", "POST"])
def editar_usuario(id):

    if "usuario_id" not in session:

        return redirect(
            url_for("inicio")
        )

    if session.get("usuario_tipo") != "gestao":

        flash(
            "Você não tem permissão para editar usuários.",
            "error"
        )

        return redirect(
            url_for("dashboard")
        )

    conexao = conectar()

    usuario = conexao.execute(
        """
        SELECT *
        FROM usuarios
        WHERE id = ?
        """,
        (id,)
    ).fetchone()

    if usuario is None:

        conexao.close()

        flash(
            "Usuário não encontrado.",
            "error"
        )

        return redirect(
            url_for("usuarios_page")
        )

    if request.method == "POST":

        nome = request.form["nome"].strip()
        email = request.form["email"].strip()
        tipo = request.form["tipo"]

        telefone = request.form.get(
            "telefone",
            ""
        ).strip()

        turma = request.form.get(
            "turma",
            ""
        ).strip()

        try:

            email_existente = conexao.execute(
                """
                SELECT id
                FROM usuarios
                WHERE email = ?
                AND id != ?
                """,
                (email, id)
            ).fetchone()

            if email_existente:

                flash(
                    "Erro: este e-mail já está sendo usado por outro usuário.",
                    "error"
                )

                conexao.close()

                return redirect(
                    url_for(
                        "editar_usuario",
                        id=id
                    )
                )

            conexao.execute(
                """
                UPDATE usuarios
                SET
                    nome = ?,
                    email = ?,
                    tipo = ?,
                    telefone = ?,
                    turma = ?
                WHERE id = ?
                """,
                (
                    nome,
                    email,
                    tipo,
                    telefone,
                    turma,
                    id
                )
            )

            conexao.commit()

            if id == session["usuario_id"]:

                session["usuario_nome"] = nome
                session["usuario_email"] = email
                session["usuario_tipo"] = tipo

            conexao.close()

            flash(
                f"Usuário {nome} atualizado com sucesso!",
                "success"
            )

            return redirect(
                url_for("usuarios_page")
            )

        except Exception as erro:

            conexao.rollback()

            print(
                "Erro ao editar usuário:",
                erro
            )

            conexao.close()

            flash(
                "Erro ao atualizar usuário.",
                "error"
            )

            return redirect(
                url_for(
                    "editar_usuario",
                    id=id
                )
            )

    turmas = conexao.execute(
        """
        SELECT *
        FROM turmas
        ORDER BY nome
        """
    ).fetchall()

    conexao.close()

    return render_template(
        "editar_usuario.html",
        usuario=usuario,
        turmas=turmas,
        usuario_nome=session["usuario_nome"],
        usuario_tipo=session["usuario_tipo"]
    )


# =========================================
# EXCLUIR USUÁRIO
# =========================================

@app.route("/usuarios/excluir/<int:id>")
def excluir_usuario(id):

    if "usuario_id" not in session:

        return redirect(
            url_for("inicio")
        )

    if session.get("usuario_tipo") != "gestao":

        flash(
            "Você não tem permissão para excluir usuários.",
            "error"
        )

        return redirect(
            url_for("dashboard")
        )

    if id == session["usuario_id"]:

        flash(
            "Você não pode excluir o usuário que está conectado.",
            "error"
        )

        return redirect(
            url_for("usuarios_page")
        )

    conexao = conectar()

    usuario = conexao.execute(
        """
        SELECT nome
        FROM usuarios
        WHERE id = ?
        """,
        (id,)
    ).fetchone()

    if usuario is None:

        conexao.close()

        flash(
            "Usuário não encontrado.",
            "error"
        )

        return redirect(
            url_for("usuarios_page")
        )

    try:

        conexao.execute(
            """
            DELETE FROM usuarios
            WHERE id = ?
            """,
            (id,)
        )

        conexao.commit()

        nome = usuario["nome"]

        conexao.close()

        flash(
            f"Usuário {nome} excluído com sucesso!",
            "success"
        )

    except Exception as erro:

        conexao.rollback()

        print(
            "Erro ao excluir usuário:",
            erro
        )

        conexao.close()

        flash(
            "Erro ao excluir usuário.",
            "error"
        )

    return redirect(
        url_for("usuarios_page")
    )


# =========================================
# TURMAS
# =========================================

@app.route("/turmas", methods=["GET", "POST"])
def turmas_page():

    if "usuario_id" not in session:

        return redirect(
            url_for("inicio")
        )

    if session.get("usuario_tipo") != "gestao":

        flash(
            "Você não tem permissão para acessar as turmas.",
            "error"
        )

        return redirect(
            url_for("dashboard")
        )

    conexao = conectar()

    if request.method == "POST":

        nome = request.form["nome"].strip()
        ano = request.form["ano"]

        turno = request.form.get(
            "turno",
            ""
        ).strip()

        curso = request.form.get(
            "curso",
            ""
        ).strip()

        try:

            turma_existente = conexao.execute(
                """
                SELECT id
                FROM turmas
                WHERE nome = ?
                """,
                (nome,)
            ).fetchone()

            if turma_existente:

                flash(
                    "Erro: esta turma já está cadastrada.",
                    "error"
                )

            else:

                conexao.execute(
                    """
                    INSERT INTO turmas
                    (
                        nome,
                        ano,
                        turno,
                        curso
                    )
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        nome,
                        ano,
                        turno,
                        curso
                    )
                )

                conexao.commit()

                flash(
                    f"Turma {nome} cadastrada com sucesso!",
                    "success"
                )

        except Exception as erro:

            conexao.rollback()

            print(
                "Erro ao cadastrar turma:",
                erro
            )

            flash(
                "Erro ao cadastrar turma.",
                "error"
            )

    turmas = conexao.execute(
        """
        SELECT
            t.*,
            COUNT(u.id) AS total_alunos
        FROM turmas t
        LEFT JOIN usuarios u
            ON u.turma = t.nome
            AND u.tipo = 'aluno'
        GROUP BY t.id
        ORDER BY t.id DESC
        """
    ).fetchall()

    conexao.close()

    return render_template(
        "turmas.html",
        turmas=turmas,
        usuario_nome=session["usuario_nome"],
        usuario_tipo=session["usuario_tipo"]
    )


# =========================================
# VER TURMA
# =========================================

@app.route("/turmas/ver/<int:id>")
def ver_turma(id):

    if "usuario_id" not in session:

        return redirect(
            url_for("inicio")
        )

    conexao = conectar()

    turma = conexao.execute(
        """
        SELECT *
        FROM turmas
        WHERE id = ?
        """,
        (id,)
    ).fetchone()

    if turma is None:

        conexao.close()

        flash(
            "Turma não encontrada.",
            "error"
        )

        return redirect(
            url_for("turmas_page")
        )

    alunos = conexao.execute(
        """
        SELECT *
        FROM usuarios
        WHERE tipo = 'aluno'
        AND turma = ?
        ORDER BY nome
        """,
        (turma["nome"],)
    ).fetchall()

    conexao.close()

    return render_template(
        "ver_turma.html",
        turma=turma,
        alunos=alunos,
        usuario_nome=session["usuario_nome"],
        usuario_tipo=session["usuario_tipo"]
    )


# =========================================
# EXCLUIR TURMA
# =========================================

@app.route("/turmas/excluir/<int:id>")
def excluir_turma(id):

    if "usuario_id" not in session:

        return redirect(
            url_for("inicio")
        )

    if session.get("usuario_tipo") != "gestao":

        flash(
            "Você não tem permissão para excluir turmas.",
            "error"
        )

        return redirect(
            url_for("dashboard")
        )

    conexao = conectar()

    turma = conexao.execute(
        """
        SELECT nome
        FROM turmas
        WHERE id = ?
        """,
        (id,)
    ).fetchone()

    if turma is None:

        conexao.close()

        flash(
            "Turma não encontrada.",
            "error"
        )

        return redirect(
            url_for("turmas_page")
        )

    try:

        alunos_vinculados = conexao.execute(
            """
            SELECT COUNT(*)
            FROM usuarios
            WHERE tipo = 'aluno'
            AND turma = ?
            """,
            (turma["nome"],)
        ).fetchone()[0]

        if alunos_vinculados > 0:

            conexao.close()

            flash(
                "Não é possível excluir esta turma porque existem alunos vinculados a ela.",
                "error"
            )

            return redirect(
                url_for("turmas_page")
            )

        conexao.execute(
            """
            DELETE FROM turmas
            WHERE id = ?
            """,
            (id,)
        )

        conexao.commit()

        nome = turma["nome"]

        conexao.close()

        flash(
            f"Turma {nome} excluída com sucesso!",
            "success"
        )

    except Exception as erro:

        conexao.rollback()

        print(
            "Erro ao excluir turma:",
            erro
        )

        conexao.close()

        flash(
            "Erro ao excluir turma.",
            "error"
        )

    return redirect(
        url_for("turmas_page")
    )


# =========================================
# EDITAR TURMA
# =========================================

@app.route("/turmas/editar/<int:id>", methods=["GET", "POST"])
def editar_turma(id):

    if "usuario_id" not in session:

        return redirect(
            url_for("inicio")
        )

    if session.get("usuario_tipo") != "gestao":

        flash(
            "Você não tem permissão para editar turmas.",
            "error"
        )

        return redirect(
            url_for("dashboard")
        )

    conexao = conectar()

    turma = conexao.execute(
        """
        SELECT *
        FROM turmas
        WHERE id = ?
        """,
        (id,)
    ).fetchone()

    if turma is None:

        conexao.close()

        flash(
            "Turma não encontrada.",
            "error"
        )

        return redirect(
            url_for("turmas_page")
        )

    if request.method == "POST":

        nome = request.form["nome"].strip()
        ano = request.form["ano"]

        turno = request.form.get(
            "turno",
            ""
        ).strip()

        curso = request.form.get(
            "curso",
            ""
        ).strip()

        try:

            turma_existente = conexao.execute(
                """
                SELECT id
                FROM turmas
                WHERE nome = ?
                AND id != ?
                """,
                (nome, id)
            ).fetchone()

            if turma_existente:

                conexao.close()

                flash(
                    "Erro: já existe outra turma com esse nome.",
                    "error"
                )

                return redirect(
                    url_for(
                        "editar_turma",
                        id=id
                    )
                )

            nome_antigo = turma["nome"]

            conexao.execute(
                """
                UPDATE turmas
                SET
                    nome = ?,
                    ano = ?,
                    turno = ?,
                    curso = ?
                WHERE id = ?
                """,
                (
                    nome,
                    ano,
                    turno,
                    curso,
                    id
                )
            )

            conexao.execute(
                """
                UPDATE usuarios
                SET turma = ?
                WHERE turma = ?
                """,
                (
                    nome,
                    nome_antigo
                )
            )

            conexao.commit()

            conexao.close()

            flash(
                f"Turma {nome} atualizada com sucesso!",
                "success"
            )

            return redirect(
                url_for("turmas_page")
            )

        except Exception as erro:

            conexao.rollback()

            print(
                "Erro ao editar turma:",
                erro
            )

            conexao.close()

            flash(
                "Erro ao atualizar turma.",
                "error"
            )

            return redirect(
                url_for(
                    "editar_turma",
                    id=id
                )
            )

    conexao.close()

    return render_template(
        "editar_turma.html",
        turma=turma,
        usuario_nome=session["usuario_nome"],
        usuario_tipo=session["usuario_tipo"]
    )


# =========================================
# PERFIL
# =========================================

@app.route("/perfil", methods=["GET", "POST"])
def perfil():

    if "usuario_id" not in session:

        return redirect(
            url_for("inicio")
        )

    conexao = conectar()

    usuario_id = session["usuario_id"]

    if request.method == "POST":

        nome = request.form["nome"].strip()
        email = request.form["email"].strip()

        telefone = request.form.get(
            "telefone",
            ""
        ).strip()

        try:

            email_existente = conexao.execute(
                """
                SELECT id
                FROM usuarios
                WHERE email = ?
                AND id != ?
                """,
                (email, usuario_id)
            ).fetchone()

            if email_existente:

                flash(
                    "Erro: este e-mail já está sendo usado por outro usuário.",
                    "error"
                )

            else:

                conexao.execute(
                    """
                    UPDATE usuarios
                    SET
                        nome = ?,
                        email = ?,
                        telefone = ?
                    WHERE id = ?
                    """,
                    (
                        nome,
                        email,
                        telefone,
                        usuario_id
                    )
                )

                conexao.commit()

                session["usuario_nome"] = nome
                session["usuario_email"] = email

                flash(
                    "Perfil atualizado com sucesso!",
                    "success"
                )

        except Exception as erro:

            conexao.rollback()

            print(
                "Erro ao atualizar perfil:",
                erro
            )

            flash(
                "Erro ao atualizar seu perfil.",
                "error"
            )

    usuario = conexao.execute(
        """
        SELECT *
        FROM usuarios
        WHERE id = ?
        """,
        (usuario_id,)
    ).fetchone()

    conexao.close()

    return render_template(
        "perfil.html",
        usuario=usuario,
        usuario_nome=session["usuario_nome"],
        usuario_tipo=session["usuario_tipo"]
    )


# =========================================
# PAINEL DO PROFESSOR
# =========================================

@app.route("/professor")
def professor():

    if "usuario_id" not in session:

        return redirect(
            url_for("inicio")
        )

    if session.get("usuario_tipo") != "professor":

        flash(
            "Acesso permitido somente para professores.",
            "error"
        )

        return redirect(
            url_for("dashboard")
        )

    conexao = conectar()

    usuario_id = session["usuario_id"]

    professor = conexao.execute(
        """
        SELECT *
        FROM usuarios
        WHERE id = ?
        AND tipo = 'professor'
        """,
        (usuario_id,)
    ).fetchone()

    if professor is None:

        conexao.close()

        session.clear()

        flash(
            "Usuário professor não encontrado.",
            "error"
        )

        return redirect(
            url_for("inicio")
        )

    turma_nome = professor["turma"]

    turmas = []
    alunos = []

    if turma_nome:

        turmas = conexao.execute(
            """
            SELECT
                t.*,
                COUNT(u.id) AS total_alunos
            FROM turmas t
            LEFT JOIN usuarios u
                ON u.turma = t.nome
                AND u.tipo = 'aluno'
            WHERE t.nome = ?
            GROUP BY t.id
            ORDER BY t.nome
            """,
            (turma_nome,)
        ).fetchall()

        alunos = conexao.execute(
            """
            SELECT *
            FROM usuarios
            WHERE tipo = 'aluno'
            AND turma = ?
            ORDER BY nome
            """,
            (turma_nome,)
        ).fetchall()

    total_alunos = len(alunos)

    avisos = conexao.execute(
        """
        SELECT *
        FROM avisos
        ORDER BY id DESC
        """
    ).fetchall()

    conexao.close()

    return render_template(
        "professor.html",
        professor=professor,
        turmas=turmas,
        alunos=alunos,
        total_alunos=total_alunos,
        avisos=avisos,
        usuario_nome=session["usuario_nome"],
        usuario_tipo=session["usuario_tipo"]
    )


# =========================================
# MEUS ALUNOS — PROFESSOR
# =========================================

@app.route("/professor/alunos")
def meus_alunos():

    if "usuario_id" not in session:

        return redirect(
            url_for("inicio")
        )

    if session.get("usuario_tipo") != "professor":

        flash(
            "Acesso permitido somente para professores.",
            "error"
        )

        return redirect(
            url_for("dashboard")
        )

    conexao = conectar()

    usuario_id = session["usuario_id"]

    professor = conexao.execute(
        """
        SELECT *
        FROM usuarios
        WHERE id = ?
        AND tipo = 'professor'
        """,
        (usuario_id,)
    ).fetchone()

    if professor is None:

        conexao.close()

        session.clear()

        flash(
            "Professor não encontrado.",
            "error"
        )

        return redirect(
            url_for("inicio")
        )

    turma_nome = professor["turma"]

    alunos = []

    if turma_nome:

        alunos = conexao.execute(
            """
            SELECT
                id,
                nome,
                email,
                telefone,
                turma
            FROM usuarios
            WHERE tipo = 'aluno'
            AND turma = ?
            ORDER BY nome
            """,
            (turma_nome,)
        ).fetchall()

    conexao.close()

    return render_template(
        "meus_alunos.html",
        professor=professor,
        alunos=alunos,
        turma_nome=turma_nome,
        usuario_nome=session["usuario_nome"],
        usuario_tipo=session["usuario_tipo"]
    )


# =========================================
# PAINEL DO ALUNO
# =========================================

@app.route("/aluno")
def aluno():

    if "usuario_id" not in session:

        return redirect(
            url_for("inicio")
        )

    if session.get("usuario_tipo") != "aluno":

        flash(
            "Acesso permitido somente para alunos.",
            "error"
        )

        return redirect(
            url_for("dashboard")
        )

    conexao = conectar()

    usuario_id = session["usuario_id"]

    aluno = conexao.execute(
        """
        SELECT *
        FROM usuarios
        WHERE id = ?
        AND tipo = 'aluno'
        """,
        (usuario_id,)
    ).fetchone()

    if aluno is None:

        conexao.close()

        session.clear()

        flash(
            "Aluno não encontrado.",
            "error"
        )

        return redirect(
            url_for("inicio")
        )

    turma = None

    if aluno["turma"]:

        turma = conexao.execute(
            """
            SELECT *
            FROM turmas
            WHERE nome = ?
            """,
            (aluno["turma"],)
        ).fetchone()

    total_alunos = 0

    if aluno["turma"]:

        total_alunos = conexao.execute(
            """
            SELECT COUNT(*)
            FROM usuarios
            WHERE tipo = 'aluno'
            AND turma = ?
            """,
            (aluno["turma"],)
        ).fetchone()[0]

    avisos = conexao.execute(
        """
        SELECT *
        FROM avisos
        ORDER BY id DESC
        """
    ).fetchall()

    conexao.close()

    return render_template(
        "aluno.html",
        aluno=aluno,
        turma=turma,
        total_alunos=total_alunos,
        avisos=avisos,
        usuario_nome=session["usuario_nome"],
        usuario_tipo=session["usuario_tipo"]
    )


# =========================================
# AVISOS — GESTÃO
# =========================================

@app.route("/avisos", methods=["GET", "POST"])
def avisos_page():

    if "usuario_id" not in session:

        return redirect(
            url_for("inicio")
        )

    if session.get("usuario_tipo") != "gestao":

        flash(
            "Somente a gestão pode administrar os avisos.",
            "error"
        )

        return redirect(
            url_for("dashboard")
        )

    conexao = conectar()

    if request.method == "POST":

        titulo = request.form["titulo"].strip()
        mensagem = request.form["mensagem"].strip()

        data = datetime.now().strftime(
            "%d/%m/%Y %H:%M"
        )

        if not titulo or not mensagem:

            flash(
                "Preencha o título e a mensagem do aviso.",
                "error"
            )

        else:

            try:

                conexao.execute(
                    """
                    INSERT INTO avisos
                    (
                        titulo,
                        mensagem,
                        data
                    )
                    VALUES (?, ?, ?)
                    """,
                    (
                        titulo,
                        mensagem,
                        data
                    )
                )

                conexao.commit()

                flash(
                    "Aviso publicado com sucesso!",
                    "success"
                )

            except Exception as erro:

                conexao.rollback()

                print(
                    "Erro ao cadastrar aviso:",
                    erro
                )

                flash(
                    "Erro ao publicar o aviso.",
                    "error"
                )

    avisos = conexao.execute(
        """
        SELECT *
        FROM avisos
        ORDER BY id DESC
        """
    ).fetchall()

    conexao.close()

    return render_template(
        "avisos.html",
        avisos=avisos,
        usuario_nome=session["usuario_nome"],
        usuario_tipo=session["usuario_tipo"]
    )


# =========================================
# EDITAR AVISO
# =========================================

@app.route("/avisos/editar/<int:id>", methods=["GET", "POST"])
def editar_aviso(id):

    if "usuario_id" not in session:

        return redirect(
            url_for("inicio")
        )

    if session.get("usuario_tipo") != "gestao":

        flash(
            "Somente a gestão pode editar avisos.",
            "error"
        )

        return redirect(
            url_for("dashboard")
        )

    conexao = conectar()

    aviso = conexao.execute(
        """
        SELECT *
        FROM avisos
        WHERE id = ?
        """,
        (id,)
    ).fetchone()

    if aviso is None:

        conexao.close()

        flash(
            "Aviso não encontrado.",
            "error"
        )

        return redirect(
            url_for("avisos_page")
        )

    if request.method == "POST":

        titulo = request.form["titulo"].strip()
        mensagem = request.form["mensagem"].strip()

        if not titulo or not mensagem:

            conexao.close()

            flash(
                "Preencha o título e a mensagem do aviso.",
                "error"
            )

            return redirect(
                url_for(
                    "editar_aviso",
                    id=id
                )
            )

        try:

            conexao.execute(
                """
                UPDATE avisos
                SET
                    titulo = ?,
                    mensagem = ?
                WHERE id = ?
                """,
                (
                    titulo,
                    mensagem,
                    id
                )
            )

            conexao.commit()

            conexao.close()

            flash(
                "Aviso atualizado com sucesso!",
                "success"
            )

            return redirect(
                url_for("avisos_page")
            )

        except Exception as erro:

            conexao.rollback()

            print(
                "Erro ao editar aviso:",
                erro
            )

            conexao.close()

            flash(
                "Erro ao atualizar o aviso.",
                "error"
            )

            return redirect(
                url_for(
                    "editar_aviso",
                    id=id
                )
            )

    conexao.close()

    return render_template(
        "editar_aviso.html",
        aviso=aviso,
        usuario_nome=session["usuario_nome"],
        usuario_tipo=session["usuario_tipo"]
    )


# =========================================
# EXCLUIR AVISO
# =========================================

@app.route("/avisos/excluir/<int:id>")
def excluir_aviso(id):

    if "usuario_id" not in session:

        return redirect(
            url_for("inicio")
        )

    if session.get("usuario_tipo") != "gestao":

        flash(
            "Somente a gestão pode excluir avisos.",
            "error"
        )

        return redirect(
            url_for("dashboard")
        )

    conexao = conectar()

    aviso = conexao.execute(
        """
        SELECT titulo
        FROM avisos
        WHERE id = ?
        """,
        (id,)
    ).fetchone()

    if aviso is None:

        conexao.close()

        flash(
            "Aviso não encontrado.",
            "error"
        )

        return redirect(
            url_for("avisos_page")
        )

    try:

        conexao.execute(
            """
            DELETE FROM avisos
            WHERE id = ?
            """,
            (id,)
        )

        conexao.commit()

        titulo = aviso["titulo"]

        conexao.close()

        flash(
            f"Aviso '{titulo}' excluído com sucesso!",
            "success"
        )

    except Exception as erro:

        conexao.rollback()

        print(
            "Erro ao excluir aviso:",
            erro
        )

        conexao.close()

        flash(
            "Erro ao excluir o aviso.",
            "error"
        )

    return redirect(
        url_for("avisos_page")
    )


# =========================================
# COMUNICAÇÃO ESCOLAR
# =========================================

@app.route("/comunicacao")
def comunicacao():

    if "usuario_id" not in session:

        return redirect(
            url_for("inicio")
        )

    conexao = conectar()

    usuario_id = session["usuario_id"]
    usuario_tipo = session["usuario_tipo"]

    contatos = []

    # =========================================
    # ALUNO
    # =========================================

    if usuario_tipo == "aluno":

        aluno = conexao.execute(
            """
            SELECT turma
            FROM usuarios
            WHERE id = ?
            """,
            (usuario_id,)
        ).fetchone()

        if aluno and aluno["turma"]:

            contatos = conexao.execute(
                """
                SELECT
                    id,
                    nome,
                    email,
                    tipo,
                    turma
                FROM usuarios
                WHERE id != ?
                AND
                (
                    tipo = 'gestao'
                    OR
                    (
                        tipo = 'professor'
                        AND turma = ?
                    )
                )
                ORDER BY
                    CASE
                        WHEN tipo = 'gestao' THEN 1
                        WHEN tipo = 'professor' THEN 2
                        ELSE 3
                    END,
                    nome
                """,
                (
                    usuario_id,
                    aluno["turma"]
                )
            ).fetchall()

        else:

            contatos = conexao.execute(
                """
                SELECT
                    id,
                    nome,
                    email,
                    tipo,
                    turma
                FROM usuarios
                WHERE id != ?
                AND tipo = 'gestao'
                ORDER BY nome
                """,
                (usuario_id,)
            ).fetchall()

    # =========================================
    # PROFESSOR
    # =========================================

    elif usuario_tipo == "professor":

        professor = conexao.execute(
            """
            SELECT turma
            FROM usuarios
            WHERE id = ?
            """,
            (usuario_id,)
        ).fetchone()

        if professor and professor["turma"]:

            contatos = conexao.execute(
                """
                SELECT
                    id,
                    nome,
                    email,
                    tipo,
                    turma
                FROM usuarios
                WHERE id != ?
                AND
                (
                    tipo = 'gestao'
                    OR
                    (
                        tipo = 'aluno'
                        AND turma = ?
                    )
                )
                ORDER BY
                    CASE
                        WHEN tipo = 'gestao' THEN 1
                        WHEN tipo = 'aluno' THEN 2
                        ELSE 3
                    END,
                    nome
                """,
                (
                    usuario_id,
                    professor["turma"]
                )
            ).fetchall()

        else:

            contatos = conexao.execute(
                """
                SELECT
                    id,
                    nome,
                    email,
                    tipo,
                    turma
                FROM usuarios
                WHERE id != ?
                AND tipo = 'gestao'
                ORDER BY nome
                """,
                (usuario_id,)
            ).fetchall()

    # =========================================
    # GESTÃO
    # =========================================

    elif usuario_tipo == "gestao":

        contatos = conexao.execute(
            """
            SELECT
                id,
                nome,
                email,
                tipo,
                turma
            FROM usuarios
            WHERE id != ?
            AND tipo IN ('professor', 'aluno')
            ORDER BY
                CASE
                    WHEN tipo = 'professor' THEN 1
                    WHEN tipo = 'aluno' THEN 2
                    ELSE 3
                END,
                nome
            """,
            (usuario_id,)
        ).fetchall()

    # =========================================
    # MENSAGENS NÃO LIDAS
    # =========================================

    contatos_com_mensagens = []

    for contato in contatos:

        nao_lidas = conexao.execute(
            """
            SELECT COUNT(*)
            FROM mensagens
            WHERE remetente_id = ?
            AND destinatario_id = ?
            AND lida = 0
            """,
            (
                contato["id"],
                usuario_id
            )
        ).fetchone()[0]

        contato_dict = dict(contato)

        contato_dict["nao_lidas"] = nao_lidas

        contatos_com_mensagens.append(
            contato_dict
        )

    conexao.close()

    return render_template(
        "comunicacao.html",
        contatos=contatos_com_mensagens,
        usuario_nome=session["usuario_nome"],
        usuario_tipo=session["usuario_tipo"]
    )


# =========================================
# CONVERSA
# =========================================

@app.route("/comunicacao/<int:contato_id>", methods=["GET", "POST"])
def conversa(contato_id):

    if "usuario_id" not in session:

        return redirect(
            url_for("inicio")
        )

    conexao = conectar()

    usuario_id = session["usuario_id"]
    usuario_tipo = session["usuario_tipo"]

    # =========================================
    # VERIFICAR CONTATO
    # =========================================

    contato = conexao.execute(
        """
        SELECT *
        FROM usuarios
        WHERE id = ?
        """,
        (contato_id,)
    ).fetchone()

    if contato is None:

        conexao.close()

        flash(
            "Usuário não encontrado.",
            "error"
        )

        return redirect(
            url_for("comunicacao")
        )

    # =========================================
    # VERIFICAR PERMISSÃO
    # =========================================

    permitido = False

    # Gestão

    if usuario_tipo == "gestao":

        if contato["tipo"] in ("professor", "aluno"):

            permitido = True

    # Professor

    elif usuario_tipo == "professor":

        if contato["tipo"] == "gestao":

            permitido = True

        elif contato["tipo"] == "aluno":

            professor = conexao.execute(
                """
                SELECT turma
                FROM usuarios
                WHERE id = ?
                """,
                (usuario_id,)
            ).fetchone()

            if professor and professor["turma"] == contato["turma"]:

                permitido = True

    # Aluno

    elif usuario_tipo == "aluno":

        if contato["tipo"] == "gestao":

            permitido = True

        elif contato["tipo"] == "professor":

            aluno = conexao.execute(
                """
                SELECT turma
                FROM usuarios
                WHERE id = ?
                """,
                (usuario_id,)
            ).fetchone()

            if aluno and aluno["turma"] == contato["turma"]:

                permitido = True

    if not permitido:

        conexao.close()

        flash(
            "Você não tem permissão para conversar com este usuário.",
            "error"
        )

        return redirect(
            url_for("comunicacao")
        )

    # =========================================
    # ENVIAR MENSAGEM
    # =========================================

    if request.method == "POST":

        mensagem = request.form.get(
            "mensagem",
            ""
        ).strip()

        if mensagem:

            data = datetime.now().strftime(
                "%d/%m/%Y %H:%M"
            )

            conexao.execute(
                """
                INSERT INTO mensagens
                (
                    remetente_id,
                    destinatario_id,
                    mensagem,
                    data,
                    lida
                )
                VALUES (?, ?, ?, ?, 0)
                """,
                (
                    usuario_id,
                    contato_id,
                    mensagem,
                    data
                )
            )

            conexao.commit()

        return redirect(
            url_for(
                "conversa",
                contato_id=contato_id
            )
        )

    # =========================================
    # BUSCAR MENSAGENS
    # =========================================

    mensagens = conexao.execute(
        """
        SELECT
            m.*,
            u.nome AS remetente_nome
        FROM mensagens m
        JOIN usuarios u
            ON u.id = m.remetente_id
        WHERE
            (
                m.remetente_id = ?
                AND m.destinatario_id = ?
            )
            OR
            (
                m.remetente_id = ?
                AND m.destinatario_id = ?
            )
        ORDER BY m.id ASC
        """,
        (
            usuario_id,
            contato_id,
            contato_id,
            usuario_id
        )
    ).fetchall()

    # =========================================
    # MARCAR COMO LIDAS
    # =========================================

    conexao.execute(
        """
        UPDATE mensagens
        SET lida = 1
        WHERE remetente_id = ?
        AND destinatario_id = ?
        """,
        (
            contato_id,
            usuario_id
        )
    )

    conexao.commit()

    conexao.close()

    return render_template(
        "conversa.html",
        contato=contato,
        mensagens=mensagens,
        usuario_id=usuario_id,
        usuario_nome=session["usuario_nome"],
        usuario_tipo=session["usuario_tipo"]
    )


# =========================================
# LOGOUT
# =========================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect(
        url_for("inicio")
    )


# =========================================
# EXECUTAR SISTEMA
# =========================================
if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )
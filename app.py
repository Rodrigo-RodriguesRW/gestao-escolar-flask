from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
    abort
)

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

from banco import conectar

from datetime import datetime

import secrets
import string
import os
import re


app = Flask(__name__)


# ============================================================
# CONFIGURAÇÃO DE SEGURANÇA
# ============================================================

app.secret_key = os.environ.get(
    "SECRET_KEY",
    secrets.token_hex(32)
)

app.config["SESSION_COOKIE_HTTPONLY"] = True

app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

app.config["SESSION_COOKIE_SECURE"] = False


# ============================================================
# CONSTANTES DE SEGURANÇA
# ============================================================

TIPOS_VALIDOS = {
    "gestao",
    "professor",
    "aluno"
}

TAMANHO_MAX_NOME = 100
TAMANHO_MAX_EMAIL = 150
TAMANHO_MAX_TELEFONE = 30
TAMANHO_MAX_TURMA = 100
TAMANHO_MAX_TITULO = 200
TAMANHO_MAX_MENSAGEM = 5000

DESTINOS_AVISO_VALIDOS = {
    "todos",
    "professores",
    "alunos",
    "turma"
}


# ============================================================
# FUNÇÕES AUXILIARES
# ============================================================

def usuario_logado():

    return "usuario_id" in session


def exigir_login():

    if not usuario_logado():

        flash(
            "Você precisa estar logado para acessar esta página.",
            "error"
        )

        return redirect(
            url_for("inicio")
        )

    return None


def exigir_tipo(tipo):

    if not usuario_logado():

        return redirect(
            url_for("inicio")
        )

    if session.get("usuario_tipo") != tipo:

        flash(
            "Você não tem permissão para acessar esta área.",
            "error"
        )

        return redirecionar_usuario()

    return None


def redirecionar_usuario():

    tipo = session.get("usuario_tipo")

    if tipo == "gestao":

        return redirect(
            url_for("dashboard")
        )

    if tipo == "professor":

        return redirect(
            url_for("professor")
        )

    if tipo == "aluno":

        return redirect(
            url_for("aluno")
        )

    session.clear()

    return redirect(
        url_for("inicio")
    )


def limpar_texto(valor, tamanho_maximo):

    if valor is None:

        return ""

    valor = str(valor).strip()

    return valor[:tamanho_maximo]


def email_valido(email):

    if not email:
        return False

    if len(email) > TAMANHO_MAX_EMAIL:
        return False

    padrao = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"

    return re.match(
        padrao,
        email
    ) is not None


def senha_valida(senha):

    if not senha:
        return False

    if len(senha) < 8:
        return False

    if len(senha) > 128:
        return False

    return True


def tipo_valido(tipo):

    return tipo in TIPOS_VALIDOS


def turma_existe(conexao, turma):

    if not turma:

        return True

    resultado = conexao.execute(
        """
        SELECT id
        FROM turmas
        WHERE nome = ?
        """,
        (turma,)
    ).fetchone()

    return resultado is not None


def gerar_senha_inicial():

    caracteres = (
        string.ascii_letters +
        string.digits
    )

    return "".join(
        secrets.choice(caracteres)
        for _ in range(10)
    )


def buscar_usuario_atual():

    if not usuario_logado():

        return None

    conexao = conectar()

    try:

        usuario = conexao.execute(
            """
            SELECT *
            FROM usuarios
            WHERE id = ?
            """,
            (session["usuario_id"],)
        ).fetchone()

        return usuario

    finally:

        conexao.close()


# ============================================================
# PROTEÇÃO GLOBAL
# ============================================================

@app.before_request
def protecao_global():

    rotas_publicas = {
        "inicio",
        "static"
    }

    if request.endpoint in rotas_publicas:

        return None

    if not usuario_logado():

        return None

    usuario = buscar_usuario_atual()

    if usuario is None:

        session.clear()

        flash(
            "Sua sessão não é mais válida.",
            "error"
        )

        return redirect(
            url_for("inicio")
        )

    session["usuario_nome"] = usuario["nome"]
    session["usuario_email"] = usuario["email"]
    session["usuario_tipo"] = usuario["tipo"]

    if (
        usuario["primeiro_acesso"] == 1
        and request.endpoint not in {
            "trocar_senha",
            "logout",
            "static"
        }
    ):

        return redirect(
            url_for("trocar_senha")
        )

    return None


# ============================================================
# LOGIN
# ============================================================

@app.route("/", methods=["GET", "POST"])
def inicio():

    if request.method == "POST":

        email = limpar_texto(
            request.form.get("email"),
            TAMANHO_MAX_EMAIL
        ).lower()

        senha = request.form.get(
            "senha",
            ""
        )

        if not email or not senha:

            flash(
                "Informe o e-mail e a senha.",
                "error"
            )

            return render_template(
                "login.html"
            )

        conexao = conectar()

        try:

            usuario = conexao.execute(
                """
                SELECT *
                FROM usuarios
                WHERE email = ?
                """,
                (email,)
            ).fetchone()

        finally:

            conexao.close()

        if usuario and check_password_hash(
            usuario["senha"],
            senha
        ):

            session.clear()

            session["usuario_id"] = usuario["id"]
            session["usuario_nome"] = usuario["nome"]
            session["usuario_email"] = usuario["email"]
            session["usuario_tipo"] = usuario["tipo"]

            if usuario["primeiro_acesso"] == 1:

                return redirect(
                    url_for("trocar_senha")
                )

            return redirecionar_usuario()

        flash(
            "E-mail ou senha inválidos.",
            "error"
        )

    return render_template(
        "login.html"
    )


# ============================================================
# PRIMEIRO ACESSO — TROCAR SENHA
# ============================================================

@app.route("/trocar-senha", methods=["GET", "POST"])
def trocar_senha():

    if not usuario_logado():

        return redirect(
            url_for("inicio")
        )

    conexao = conectar()

    try:

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

            session.clear()

            flash(
                "Usuário não encontrado.",
                "error"
            )

            return redirect(
                url_for("inicio")
            )

        if usuario["primeiro_acesso"] == 0:

            return redirecionar_usuario()

        if request.method == "POST":

            nova_senha = request.form.get(
                "nova_senha",
                ""
            ).strip()

            confirmar_senha = request.form.get(
                "confirmar_senha",
                ""
            ).strip()

            if not nova_senha or not confirmar_senha:

                flash(
                    "Preencha os dois campos de senha.",
                    "error"
                )

                return render_template(
                    "trocar_senha.html",
                    usuario_nome=usuario["nome"],
                    usuario_tipo=usuario["tipo"]
                )

            if nova_senha != confirmar_senha:

                flash(
                    "As senhas não são iguais.",
                    "error"
                )

                return render_template(
                    "trocar_senha.html",
                    usuario_nome=usuario["nome"],
                    usuario_tipo=usuario["tipo"]
                )

            if not senha_valida(nova_senha):

                flash(
                    "A nova senha deve possuir entre 8 e 128 caracteres.",
                    "error"
                )

                return render_template(
                    "trocar_senha.html",
                    usuario_nome=usuario["nome"],
                    usuario_tipo=usuario["tipo"]
                )

            senha_hash = generate_password_hash(
                nova_senha
            )

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

            session["usuario_nome"] = usuario["nome"]
            session["usuario_email"] = usuario["email"]
            session["usuario_tipo"] = usuario["tipo"]

            flash(
                "Senha criada com sucesso!",
                "success"
            )

            return redirecionar_usuario()

        return render_template(
            "trocar_senha.html",
            usuario_nome=usuario["nome"],
            usuario_tipo=usuario["tipo"]
        )

    except Exception as erro:

        conexao.rollback()

        print(
            "Erro ao alterar senha:",
            erro
        )

        flash(
            "Erro ao criar a nova senha.",
            "error"
        )

        return redirect(
            url_for("inicio")
        )

    finally:

        conexao.close()


# ============================================================
# DASHBOARD DA GESTÃO
# ============================================================

@app.route("/dashboard")
def dashboard():

    acesso = exigir_tipo("gestao")

    if acesso:

        return acesso

    conexao = conectar()

    try:

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

    finally:

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


# ============================================================
# USUÁRIOS
# ============================================================

@app.route("/usuarios", methods=["GET", "POST"])
def usuarios_page():

    acesso = exigir_tipo("gestao")

    if acesso:

        return acesso

    conexao = conectar()

    try:

        if request.method == "POST":

            nome = limpar_texto(
                request.form.get("nome"),
                TAMANHO_MAX_NOME
            )

            email = limpar_texto(
                request.form.get("email"),
                TAMANHO_MAX_EMAIL
            ).lower()

            tipo = limpar_texto(
                request.form.get("tipo"),
                30
            )

            telefone = limpar_texto(
                request.form.get("telefone"),
                TAMANHO_MAX_TELEFONE
            )

            turma = limpar_texto(
                request.form.get("turma"),
                TAMANHO_MAX_TURMA
            )

            if not nome:

                flash(
                    "Informe o nome do usuário.",
                    "error"
                )

            elif not email_valido(email):

                flash(
                    "Informe um e-mail válido.",
                    "error"
                )

            elif not tipo_valido(tipo):

                flash(
                    "Tipo de usuário inválido.",
                    "error"
                )

            elif not turma_existe(conexao, turma):

                flash(
                    "A turma informada não existe.",
                    "error"
                )

            else:

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

                    senha_inicial = gerar_senha_inicial()

                    senha_hash = generate_password_hash(
                        senha_inicial
                    )

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
                            senha_hash,
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

    except Exception as erro:

        conexao.rollback()

        print(
            "Erro na área de usuários:",
            erro
        )

        flash(
            "Erro ao processar usuário.",
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

    finally:

        conexao.close()

    return render_template(
        "usuarios.html",
        usuarios=usuarios,
        turmas=turmas,
        usuario_nome=session["usuario_nome"],
        usuario_tipo=session["usuario_tipo"]
    )


# ============================================================
# EDITAR USUÁRIO
# ============================================================

@app.route(
    "/usuarios/editar/<int:id>",
    methods=["GET", "POST"]
)
def editar_usuario(id):

    acesso = exigir_tipo("gestao")

    if acesso:

        return acesso

    conexao = conectar()

    try:

        usuario = conexao.execute(
            """
            SELECT *
            FROM usuarios
            WHERE id = ?
            """,
            (id,)
        ).fetchone()

        if usuario is None:

            flash(
                "Usuário não encontrado.",
                "error"
            )

            return redirect(
                url_for("usuarios_page")
            )

        if request.method == "POST":

            nome = limpar_texto(
                request.form.get("nome"),
                TAMANHO_MAX_NOME
            )

            email = limpar_texto(
                request.form.get("email"),
                TAMANHO_MAX_EMAIL
            ).lower()

            tipo = limpar_texto(
                request.form.get("tipo"),
                30
            )

            telefone = limpar_texto(
                request.form.get("telefone"),
                TAMANHO_MAX_TELEFONE
            )

            turma = limpar_texto(
                request.form.get("turma"),
                TAMANHO_MAX_TURMA
            )

            if not nome:

                flash(
                    "Informe o nome do usuário.",
                    "error"
                )

                return redirect(
                    url_for(
                        "editar_usuario",
                        id=id
                    )
                )

            if not email_valido(email):

                flash(
                    "Informe um e-mail válido.",
                    "error"
                )

                return redirect(
                    url_for(
                        "editar_usuario",
                        id=id
                    )
                )

            if not tipo_valido(tipo):

                flash(
                    "Tipo de usuário inválido.",
                    "error"
                )

                return redirect(
                    url_for(
                        "editar_usuario",
                        id=id
                    )
                )

            if not turma_existe(conexao, turma):

                flash(
                    "A turma informada não existe.",
                    "error"
                )

                return redirect(
                    url_for(
                        "editar_usuario",
                        id=id
                    )
                )

            email_existente = conexao.execute(
                """
                SELECT id
                FROM usuarios
                WHERE email = ?
                AND id != ?
                """,
                (
                    email,
                    id
                )
            ).fetchone()

            if email_existente:

                flash(
                    "Erro: este e-mail já está sendo usado por outro usuário.",
                    "error"
                )

                return redirect(
                    url_for(
                        "editar_usuario",
                        id=id
                    )
                )

            if tipo in ("aluno", "professor") and not turma:

                flash(
                    "Aluno e professor devem possuir uma turma vinculada.",
                    "error"
                )

                return redirect(
                    url_for(
                        "editar_usuario",
                        id=id
                    )
                )

            if (
                usuario["tipo"] == "gestao"
                and tipo != "gestao"
            ):

                total_gestao = conexao.execute(
                    """
                    SELECT COUNT(*)
                    FROM usuarios
                    WHERE tipo = 'gestao'
                    """
                ).fetchone()[0]

                if total_gestao <= 1:

                    flash(
                        "O sistema precisa possuir pelo menos um usuário da gestão.",
                        "error"
                    )

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

            flash(
                f"Usuário {nome} atualizado com sucesso!",
                "success"
            )

            return redirect(
                url_for("usuarios_page")
            )

        turmas = conexao.execute(
            """
            SELECT *
            FROM turmas
            ORDER BY nome
            """
        ).fetchall()

    except Exception as erro:

        conexao.rollback()

        print(
            "Erro ao editar usuário:",
            erro
        )

        flash(
            "Erro ao atualizar usuário.",
            "error"
        )

        return redirect(
            url_for(
                "usuarios_page"
            )
        )

    finally:

        conexao.close()

    return render_template(
        "editar_usuario.html",
        usuario=usuario,
        turmas=turmas,
        usuario_nome=session["usuario_nome"],
        usuario_tipo=session["usuario_tipo"]
    )


# ============================================================
# EXCLUIR USUÁRIO
# ============================================================

@app.route("/usuarios/excluir/<int:id>")
def excluir_usuario(id):

    acesso = exigir_tipo("gestao")

    if acesso:

        return acesso

    if id == session["usuario_id"]:

        flash(
            "Você não pode excluir o usuário que está conectado.",
            "error"
        )

        return redirect(
            url_for("usuarios_page")
        )

    conexao = conectar()

    try:

        usuario = conexao.execute(
            """
            SELECT *
            FROM usuarios
            WHERE id = ?
            """,
            (id,)
        ).fetchone()

        if usuario is None:

            flash(
                "Usuário não encontrado.",
                "error"
            )

            return redirect(
                url_for("usuarios_page")
            )

        if usuario["tipo"] == "gestao":

            total_gestao = conexao.execute(
                """
                SELECT COUNT(*)
                FROM usuarios
                WHERE tipo = 'gestao'
                """
            ).fetchone()[0]

            if total_gestao <= 1:

                flash(
                    "Não é possível excluir o último usuário da gestão.",
                    "error"
                )

                return redirect(
                    url_for("usuarios_page")
                )

        conexao.execute(
            """
            DELETE FROM usuarios
            WHERE id = ?
            """,
            (id,)
        )

        conexao.commit()

        flash(
            f"Usuário {usuario['nome']} excluído com sucesso!",
            "success"
        )

    except Exception as erro:

        conexao.rollback()

        print(
            "Erro ao excluir usuário:",
            erro
        )

        flash(
            "Erro ao excluir usuário.",
            "error"
        )

    finally:

        conexao.close()

    return redirect(
        url_for("usuarios_page")
    )


# ============================================================
# TURMAS
# ============================================================

@app.route("/turmas", methods=["GET", "POST"])
def turmas_page():

    acesso = exigir_tipo("gestao")

    if acesso:

        return acesso

    conexao = conectar()

    try:

        if request.method == "POST":

            nome = limpar_texto(
                request.form.get("nome"),
                TAMANHO_MAX_TURMA
            )

            ano = limpar_texto(
                request.form.get("ano"),
                10
            )

            turno = limpar_texto(
                request.form.get("turno"),
                30
            )

            curso = limpar_texto(
                request.form.get("curso"),
                100
            )

            if not nome:

                flash(
                    "Informe o nome da turma.",
                    "error"
                )

            else:

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

    except Exception as erro:

        conexao.rollback()

        print(
            "Erro ao cadastrar turma:",
            erro
        )

        flash(
            "Erro ao processar turma.",
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

    finally:

        conexao.close()

    return render_template(
        "turmas.html",
        turmas=turmas,
        usuario_nome=session["usuario_nome"],
        usuario_tipo=session["usuario_tipo"]
    )


# ============================================================
# VER TURMA
# ============================================================

@app.route("/turmas/ver/<int:id>")
def ver_turma(id):

    acesso = exigir_tipo("gestao")

    if acesso:

        return acesso

    conexao = conectar()

    try:

        turma = conexao.execute(
            """
            SELECT *
            FROM turmas
            WHERE id = ?
            """,
            (id,)
        ).fetchone()

        if turma is None:

            flash(
                "Turma não encontrada.",
                "error"
            )

            return redirect(
                url_for("turmas_page")
            )

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
            (turma["nome"],)
        ).fetchall()

    finally:

        conexao.close()

    return render_template(
        "ver_turma.html",
        turma=turma,
        alunos=alunos,
        usuario_nome=session["usuario_nome"],
        usuario_tipo=session["usuario_tipo"]
    )


# ============================================================
# EXCLUIR TURMA
# ============================================================

@app.route("/turmas/excluir/<int:id>")
def excluir_turma(id):

    acesso = exigir_tipo("gestao")

    if acesso:

        return acesso

    conexao = conectar()

    try:

        turma = conexao.execute(
            """
            SELECT *
            FROM turmas
            WHERE id = ?
            """,
            (id,)
        ).fetchone()

        if turma is None:

            flash(
                "Turma não encontrada.",
                "error"
            )

            return redirect(
                url_for("turmas_page")
            )

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

            flash(
                "Não é possível excluir esta turma porque existem alunos vinculados a ela.",
                "error"
            )

            return redirect(
                url_for("turmas_page")
            )

        professores_vinculados = conexao.execute(
            """
            SELECT COUNT(*)
            FROM usuarios
            WHERE tipo = 'professor'
            AND turma = ?
            """,
            (turma["nome"],)
        ).fetchone()[0]

        if professores_vinculados > 0:

            flash(
                "Não é possível excluir esta turma porque existem professores vinculados a ela.",
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

        flash(
            f"Turma {turma['nome']} excluída com sucesso!",
            "success"
        )

    except Exception as erro:

        conexao.rollback()

        print(
            "Erro ao excluir turma:",
            erro
        )

        flash(
            "Erro ao excluir turma.",
            "error"
        )

    finally:

        conexao.close()

    return redirect(
        url_for("turmas_page")
    )


# ============================================================
# EDITAR TURMA
# ============================================================

@app.route(
    "/turmas/editar/<int:id>",
    methods=["GET", "POST"]
)
def editar_turma(id):

    acesso = exigir_tipo("gestao")

    if acesso:

        return acesso

    conexao = conectar()

    try:

        turma = conexao.execute(
            """
            SELECT *
            FROM turmas
            WHERE id = ?
            """,
            (id,)
        ).fetchone()

        if turma is None:

            flash(
                "Turma não encontrada.",
                "error"
            )

            return redirect(
                url_for("turmas_page")
            )

        if request.method == "POST":

            nome = limpar_texto(
                request.form.get("nome"),
                TAMANHO_MAX_TURMA
            )

            ano = limpar_texto(
                request.form.get("ano"),
                10
            )

            turno = limpar_texto(
                request.form.get("turno"),
                30
            )

            curso = limpar_texto(
                request.form.get("curso"),
                100
            )

            if not nome:

                flash(
                    "Informe o nome da turma.",
                    "error"
                )

                return redirect(
                    url_for(
                        "editar_turma",
                        id=id
                    )
                )

            turma_existente = conexao.execute(
                """
                SELECT id
                FROM turmas
                WHERE nome = ?
                AND id != ?
                """,
                (
                    nome,
                    id
                )
            ).fetchone()

            if turma_existente:

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

    finally:

        conexao.close()

    return render_template(
        "editar_turma.html",
        turma=turma,
        usuario_nome=session["usuario_nome"],
        usuario_tipo=session["usuario_tipo"]
    )


# ============================================================
# PERFIL
# ============================================================

@app.route(
    "/perfil",
    methods=["GET", "POST"]
)
def perfil():

    acesso = exigir_login()

    if acesso:

        return acesso

    conexao = conectar()

    try:

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

            session.clear()

            flash(
                "Usuário não encontrado.",
                "error"
            )

            return redirect(
                url_for("inicio")
            )

        if request.method == "POST":

            nome = limpar_texto(
                request.form.get("nome"),
                TAMANHO_MAX_NOME
            )

            email = limpar_texto(
                request.form.get("email"),
                TAMANHO_MAX_EMAIL
            ).lower()

            telefone = limpar_texto(
                request.form.get("telefone"),
                TAMANHO_MAX_TELEFONE
            )

            if not nome:

                flash(
                    "Informe seu nome.",
                    "error"
                )

            elif not email_valido(email):

                flash(
                    "Informe um e-mail válido.",
                    "error"
                )

            else:

                email_existente = conexao.execute(
                    """
                    SELECT id
                    FROM usuarios
                    WHERE email = ?
                    AND id != ?
                    """,
                    (
                        email,
                        usuario_id
                    )
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

        usuario = conexao.execute(
            """
            SELECT *
            FROM usuarios
            WHERE id = ?
            """,
            (usuario_id,)
        ).fetchone()

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

    finally:

        conexao.close()

    return render_template(
        "perfil.html",
        usuario=usuario,
        usuario_nome=session["usuario_nome"],
        usuario_tipo=session["usuario_tipo"]
    )


# ============================================================
# PAINEL DO PROFESSOR
# ============================================================

@app.route("/professor")
def professor():

    acesso = exigir_tipo("professor")

    if acesso:

        return acesso

    conexao = conectar()

    try:

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

        total_alunos = len(alunos)

        # =====================================================
        # PROFESSOR:
        # TODOS + SOMENTE PROFESSORES
        # =====================================================

        avisos = conexao.execute(
            """
            SELECT *
            FROM avisos
            WHERE
                COALESCE(destino, 'todos') IN (
                    'todos',
                    'professores'
                )
            ORDER BY id DESC
            """
        ).fetchall()

    finally:

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


# ============================================================
# MINHAS TURMAS — PROFESSOR
# ============================================================

@app.route("/professor/turmas")
def professor_turmas():

    acesso = exigir_tipo("professor")

    if acesso:

        return acesso

    conexao = conectar()

    try:

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

            session.clear()

            flash(
                "Professor não encontrado.",
                "error"
            )

            return redirect(
                url_for("inicio")
            )

        turma = None
        alunos = []

        if professor["turma"]:

            turma = conexao.execute(
                """
                SELECT *
                FROM turmas
                WHERE nome = ?
                """,
                (professor["turma"],)
            ).fetchone()

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
                (professor["turma"],)
            ).fetchall()

    finally:

        conexao.close()

    return render_template(
        "professor_turmas.html",
        professor=professor,
        turma=turma,
        alunos=alunos,
        usuario_nome=session["usuario_nome"],
        usuario_tipo=session["usuario_tipo"]
    )


# ============================================================
# AVISOS — PROFESSOR
# ============================================================

@app.route("/professor/avisos")
def professor_avisos():

    acesso = exigir_tipo("professor")

    if acesso:

        return acesso

    conexao = conectar()

    try:

        avisos = conexao.execute(
            """
            SELECT *
            FROM avisos
            WHERE
                COALESCE(destino, 'todos') IN (
                    'todos',
                    'professores'
                )
            ORDER BY id DESC
            """
        ).fetchall()

    finally:

        conexao.close()

    return render_template(
        "professor_avisos.html",
        avisos=avisos,
        usuario_nome=session["usuario_nome"],
        usuario_tipo=session["usuario_tipo"]
    )


# ============================================================
# MEUS ALUNOS — PROFESSOR
# ============================================================

@app.route("/professor/alunos")
def meus_alunos():

    acesso = exigir_tipo("professor")

    if acesso:

        return acesso

    conexao = conectar()

    try:

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

    finally:

        conexao.close()

    return render_template(
        "meus_alunos.html",
        professor=professor,
        alunos=alunos,
        turma_nome=turma_nome,
        usuario_nome=session["usuario_nome"],
        usuario_tipo=session["usuario_tipo"]
    )


# ============================================================
# PAINEL DO ALUNO
# ============================================================

@app.route("/aluno")
def aluno():

    acesso = exigir_tipo("aluno")

    if acesso:

        return acesso

    conexao = conectar()

    try:

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

            session.clear()

            flash(
                "Aluno não encontrado.",
                "error"
            )

            return redirect(
                url_for("inicio")
            )

        turma = None
        total_alunos = 0

        if aluno["turma"]:

            turma = conexao.execute(
                """
                SELECT *
                FROM turmas
                WHERE nome = ?
                """,
                (aluno["turma"],)
            ).fetchone()

            total_alunos = conexao.execute(
                """
                SELECT COUNT(*)
                FROM usuarios
                WHERE tipo = 'aluno'
                AND turma = ?
                """,
                (aluno["turma"],)
            ).fetchone()[0]

        # =====================================================
        # ALUNO:
        # TODOS + ALUNOS + SUA TURMA
        # =====================================================

        avisos = conexao.execute(
            """
            SELECT *
            FROM avisos
            WHERE
                COALESCE(destino, 'todos') IN (
                    'todos',
                    'alunos'
                )
                OR
                (
                    destino = 'turma'
                    AND turma = ?
                )
            ORDER BY id DESC
            """,
            (aluno["turma"],)
        ).fetchall()

    finally:

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


# ============================================================
# MINHA TURMA — ALUNO
# ============================================================

@app.route("/aluno/turma")
def aluno_turma():

    acesso = exigir_tipo("aluno")

    if acesso:

        return acesso

    conexao = conectar()

    try:

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

            session.clear()

            flash(
                "Aluno não encontrado.",
                "error"
            )

            return redirect(
                url_for("inicio")
            )

        turma = None
        colegas = []

        if aluno["turma"]:

            turma = conexao.execute(
                """
                SELECT *
                FROM turmas
                WHERE nome = ?
                """,
                (aluno["turma"],)
            ).fetchone()

            colegas = conexao.execute(
                """
                SELECT
                    id,
                    nome,
                    email,
                    turma
                FROM usuarios
                WHERE tipo = 'aluno'
                AND turma = ?
                AND id != ?
                ORDER BY nome
                """,
                (
                    aluno["turma"],
                    usuario_id
                )
            ).fetchall()

    finally:

        conexao.close()

    return render_template(
        "aluno_turma.html",
        aluno=aluno,
        turma=turma,
        colegas=colegas,
        usuario_nome=session["usuario_nome"],
        usuario_tipo=session["usuario_tipo"]
    )


# ============================================================
# PROFESSORES — ALUNO
# ============================================================

@app.route("/aluno/professores")
def aluno_professores():

    acesso = exigir_tipo("aluno")

    if acesso:

        return acesso

    conexao = conectar()

    try:

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

            session.clear()

            flash(
                "Aluno não encontrado.",
                "error"
            )

            return redirect(
                url_for("inicio")
            )

        professores = []

        if aluno["turma"]:

            professores = conexao.execute(
                """
                SELECT
                    id,
                    nome,
                    email,
                    telefone,
                    turma
                FROM usuarios
                WHERE tipo = 'professor'
                AND turma = ?
                ORDER BY nome
                """,
                (aluno["turma"],)
            ).fetchall()

    finally:

        conexao.close()

    return render_template(
        "aluno_professores.html",
        aluno=aluno,
        professores=professores,
        usuario_nome=session["usuario_nome"],
        usuario_tipo=session["usuario_tipo"]
    )


# ============================================================
# AVISOS — ALUNO
# ============================================================

@app.route("/aluno/avisos")
def aluno_avisos():

    acesso = exigir_tipo("aluno")

    if acesso:

        return acesso

    conexao = conectar()

    try:

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

            session.clear()

            flash(
                "Aluno não encontrado.",
                "error"
            )

            return redirect(
                url_for("inicio")
            )

        avisos = conexao.execute(
            """
            SELECT *
            FROM avisos
            WHERE
                COALESCE(destino, 'todos') IN (
                    'todos',
                    'alunos'
                )
                OR
                (
                    destino = 'turma'
                    AND turma = ?
                )
            ORDER BY id DESC
            """,
            (aluno["turma"],)
        ).fetchall()

    finally:

        conexao.close()

    return render_template(
        "aluno_avisos.html",
        avisos=avisos,
        usuario_nome=session["usuario_nome"],
        usuario_tipo=session["usuario_tipo"]
    )


# ============================================================
# AVISOS — GESTÃO
# ============================================================

@app.route(
    "/avisos",
    methods=["GET", "POST"]
)
def avisos_page():

    acesso = exigir_tipo("gestao")

    if acesso:

        return acesso

    conexao = conectar()

    try:

        if request.method == "POST":

            titulo = limpar_texto(
                request.form.get("titulo"),
                TAMANHO_MAX_TITULO
            )

            mensagem = limpar_texto(
                request.form.get("mensagem"),
                TAMANHO_MAX_MENSAGEM
            )

            destino = limpar_texto(
                request.form.get("destino"),
                30
            )

            turma = limpar_texto(
                request.form.get("turma"),
                TAMANHO_MAX_TURMA
            )

            # =================================================
            # VALIDAÇÕES
            # =================================================

            if not titulo or not mensagem:

                flash(
                    "Preencha o título e a mensagem do aviso.",
                    "error"
                )

            elif destino not in DESTINOS_AVISO_VALIDOS:

                flash(
                    "Destino do aviso inválido.",
                    "error"
                )

            elif destino == "turma" and not turma:

                flash(
                    "Selecione uma turma para este aviso.",
                    "error"
                )

            elif destino == "turma" and not turma_existe(
                conexao,
                turma
            ):

                flash(
                    "A turma selecionada não existe.",
                    "error"
                )

            else:

                data = datetime.now().strftime(
                    "%d/%m/%Y %H:%M"
                )

                if destino != "turma":

                    turma = ""

                conexao.execute(
                    """
                    INSERT INTO avisos
                    (
                        titulo,
                        mensagem,
                        data,
                        destino,
                        turma
                    )
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        titulo,
                        mensagem,
                        data,
                        destino,
                        turma
                    )
                )

                conexao.commit()

                flash(
                    "Aviso publicado com sucesso!",
                    "success"
                )

        avisos = conexao.execute(
            """
            SELECT *
            FROM avisos
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

        turmas = conexao.execute(
            """
            SELECT *
            FROM turmas
            ORDER BY nome
            """
        ).fetchall()

    finally:

        conexao.close()

    return render_template(
        "avisos.html",
        avisos=avisos,
        turmas=turmas,
        usuario_nome=session["usuario_nome"],
        usuario_tipo=session["usuario_tipo"]
    )


# ============================================================
# EDITAR AVISO
# ============================================================

@app.route(
    "/avisos/editar/<int:id>",
    methods=["GET", "POST"]
)
def editar_aviso(id):

    acesso = exigir_tipo("gestao")

    if acesso:

        return acesso

    conexao = conectar()

    try:

        aviso = conexao.execute(
            """
            SELECT *
            FROM avisos
            WHERE id = ?
            """,
            (id,)
        ).fetchone()

        if aviso is None:

            flash(
                "Aviso não encontrado.",
                "error"
            )

            return redirect(
                url_for("avisos_page")
            )

        if request.method == "POST":

            titulo = limpar_texto(
                request.form.get("titulo"),
                TAMANHO_MAX_TITULO
            )

            mensagem = limpar_texto(
                request.form.get("mensagem"),
                TAMANHO_MAX_MENSAGEM
            )

            destino = limpar_texto(
                request.form.get("destino"),
                30
            )

            turma = limpar_texto(
                request.form.get("turma"),
                TAMANHO_MAX_TURMA
            )

            # =================================================
            # VALIDAÇÕES
            # =================================================

            if not titulo or not mensagem:

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

            if destino not in DESTINOS_AVISO_VALIDOS:

                flash(
                    "Destino do aviso inválido.",
                    "error"
                )

                return redirect(
                    url_for(
                        "editar_aviso",
                        id=id
                    )
                )

            if destino == "turma" and not turma:

                flash(
                    "Selecione uma turma para este aviso.",
                    "error"
                )

                return redirect(
                    url_for(
                        "editar_aviso",
                        id=id
                    )
                )

            if destino == "turma" and not turma_existe(
                conexao,
                turma
            ):

                flash(
                    "A turma selecionada não existe.",
                    "error"
                )

                return redirect(
                    url_for(
                        "editar_aviso",
                        id=id
                    )
                )

            if destino != "turma":

                turma = ""

            conexao.execute(
                """
                UPDATE avisos
                SET
                    titulo = ?,
                    mensagem = ?,
                    destino = ?,
                    turma = ?
                WHERE id = ?
                """,
                (
                    titulo,
                    mensagem,
                    destino,
                    turma,
                    id
                )
            )

            conexao.commit()

            flash(
                "Aviso atualizado com sucesso!",
                "success"
            )

            return redirect(
                url_for("avisos_page")
            )

        turmas = conexao.execute(
            """
            SELECT *
            FROM turmas
            ORDER BY nome
            """
        ).fetchall()

    except Exception as erro:

        conexao.rollback()

        print(
            "Erro ao editar aviso:",
            erro
        )

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

    finally:

        conexao.close()

    return render_template(
        "editar_aviso.html",
        aviso=aviso,
        turmas=turmas,
        usuario_nome=session["usuario_nome"],
        usuario_tipo=session["usuario_tipo"]
    )


# ============================================================
# EXCLUIR AVISO
# ============================================================

@app.route("/avisos/excluir/<int:id>")
def excluir_aviso(id):

    acesso = exigir_tipo("gestao")

    if acesso:

        return acesso

    conexao = conectar()

    try:

        aviso = conexao.execute(
            """
            SELECT titulo
            FROM avisos
            WHERE id = ?
            """,
            (id,)
        ).fetchone()

        if aviso is None:

            flash(
                "Aviso não encontrado.",
                "error"
            )

            return redirect(
                url_for("avisos_page")
            )

        conexao.execute(
            """
            DELETE FROM avisos
            WHERE id = ?
            """,
            (id,)
        )

        conexao.commit()

        flash(
            f"Aviso '{aviso['titulo']}' excluído com sucesso!",
            "success"
        )

    except Exception as erro:

        conexao.rollback()

        print(
            "Erro ao excluir aviso:",
            erro
        )

        flash(
            "Erro ao excluir o aviso.",
            "error"
        )

    finally:

        conexao.close()

    return redirect(
        url_for("avisos_page")
    )


# ============================================================
# COMUNICAÇÃO ESCOLAR
# ============================================================

@app.route("/comunicacao")
def comunicacao():

    acesso = exigir_login()

    if acesso:

        return acesso

    conexao = conectar()

    try:

        usuario_id = session["usuario_id"]
        usuario_tipo = session["usuario_tipo"]

        contatos = []

        # =====================================================
        # ALUNO
        # =====================================================

        if usuario_tipo == "aluno":

            aluno = conexao.execute(
                """
                SELECT turma
                FROM usuarios
                WHERE id = ?
                AND tipo = 'aluno'
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

        # =====================================================
        # PROFESSOR
        # =====================================================

        elif usuario_tipo == "professor":

            professor = conexao.execute(
                """
                SELECT turma
                FROM usuarios
                WHERE id = ?
                AND tipo = 'professor'
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

        # =====================================================
        # GESTÃO
        # =====================================================

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

    finally:

        conexao.close()

    return render_template(
        "comunicacao.html",
        contatos=contatos_com_mensagens,
        usuario_nome=session["usuario_nome"],
        usuario_tipo=session["usuario_tipo"]
    )


# ============================================================
# CONVERSA
# ============================================================

@app.route(
    "/comunicacao/<int:contato_id>",
    methods=["GET", "POST"]
)
def conversa(contato_id):

    acesso = exigir_login()

    if acesso:

        return acesso

    conexao = conectar()

    try:

        usuario_id = session["usuario_id"]
        usuario_tipo = session["usuario_tipo"]

        if contato_id == usuario_id:

            flash(
                "Você não pode conversar consigo mesmo.",
                "error"
            )

            return redirect(
                url_for("comunicacao")
            )

        contato = conexao.execute(
            """
            SELECT *
            FROM usuarios
            WHERE id = ?
            """,
            (contato_id,)
        ).fetchone()

        if contato is None:

            flash(
                "Usuário não encontrado.",
                "error"
            )

            return redirect(
                url_for("comunicacao")
            )

        permitido = False

        # =====================================================
        # GESTÃO
        # =====================================================

        if usuario_tipo == "gestao":

            if contato["tipo"] in (
                "professor",
                "aluno"
            ):

                permitido = True

        # =====================================================
        # PROFESSOR
        # =====================================================

        elif usuario_tipo == "professor":

            if contato["tipo"] == "gestao":

                permitido = True

            elif contato["tipo"] == "aluno":

                professor = conexao.execute(
                    """
                    SELECT turma
                    FROM usuarios
                    WHERE id = ?
                    AND tipo = 'professor'
                    """,
                    (usuario_id,)
                ).fetchone()

                if (
                    professor
                    and professor["turma"]
                    and professor["turma"] == contato["turma"]
                ):

                    permitido = True

        # =====================================================
        # ALUNO
        # =====================================================

        elif usuario_tipo == "aluno":

            if contato["tipo"] == "gestao":

                permitido = True

            elif contato["tipo"] == "professor":

                aluno = conexao.execute(
                    """
                    SELECT turma
                    FROM usuarios
                    WHERE id = ?
                    AND tipo = 'aluno'
                    """,
                    (usuario_id,)
                ).fetchone()

                if (
                    aluno
                    and aluno["turma"]
                    and aluno["turma"] == contato["turma"]
                ):

                    permitido = True

        if not permitido:

            flash(
                "Você não tem permissão para conversar com este usuário.",
                "error"
            )

            return redirect(
                url_for("comunicacao")
            )

        # =====================================================
        # ENVIAR MENSAGEM
        # =====================================================

        if request.method == "POST":

            mensagem = limpar_texto(
                request.form.get("mensagem"),
                TAMANHO_MAX_MENSAGEM
            )

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

        # =====================================================
        # BUSCAR MENSAGENS
        # =====================================================

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

        # =====================================================
        # MARCAR COMO LIDAS
        # =====================================================

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

    finally:

        conexao.close()

    return render_template(
        "conversa.html",
        contato=contato,
        mensagens=mensagens,
        usuario_id=usuario_id,
        usuario_nome=session["usuario_nome"],
        usuario_tipo=session["usuario_tipo"]
    )


# ============================================================
# LOGOUT
# ============================================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect(
        url_for("inicio")
    )


# ============================================================
# ERROS
# ============================================================

@app.errorhandler(404)
def pagina_nao_encontrada(erro):

    return (
        """
        <h1>404 - Página não encontrada</h1>
        <p>A página solicitada não existe.</p>
        """,
        404
    )


@app.errorhandler(403)
def acesso_negado(erro):

    return (
        """
        <h1>403 - Acesso negado</h1>
        <p>Você não possui permissão para acessar este recurso.</p>
        """,
        403
    )


@app.errorhandler(500)
def erro_interno(erro):

    return (
        """
        <h1>500 - Erro interno</h1>
        <p>O sistema encontrou um erro inesperado.</p>
        """,
        500
    )


# ============================================================
# EXECUTAR SISTEMA
# ============================================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False
    )
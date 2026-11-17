import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from database import Base, get_db
from main import app


#banco SQLite em memória isolado para não alterar o banco livraria.db durante os testes
SQLALCHEMY_DATABASE_URL = "sqlite://"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


#substitui a dependência get_db original pela sessão do banco de testes
def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()
#--------------------------

app.dependency_overrides[get_db] = override_get_db
client = TestClient(app)


#fixture executada automaticamente antes e depois de cada teste para isolar os dados
@pytest.fixture(autouse=True)
def setup_database():
    """Cria as tabelas antes de cada teste e limpa ao final."""
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)
#--------------------------

# 1- testa se a rota pública inicial (GET /) responde com status 200 OK
def test_read_root_returns_200():
    response = client.get("/")
    assert response.status_code == 200
    assert "Mensagem" in response.json()
#--------------------------

# 2- testa se buscar um livro inexistente retorna erro 404 Not Found
def test_get_nonexistent_book_returns_404():
    response = client.get("/books/999")
    assert response.status_code == 404
    assert response.json()["detail"] == "Livro não encontrado."
#--------------------------

# 3- testa se tentar criar um livro sem token JWT é bloqueado com status 401 Unauthorized
def test_create_book_without_token_returns_401():
    response = client.post(
        "/books/",
        json={"name": "Clean Code", "description": "Habilidades Práticas", "price": 89.90},
    )
    assert response.status_code == 401
#--------------------------

# 4- testa se acessar os dados do usuário logado sem token retorna erro 401 Unauthorized
def test_read_users_me_without_token_returns_401():
    response = client.get("/users/me")
    assert response.status_code == 401
#--------------------------

# 5- testa o fluxo completo de cadastro de usuário e login gerando token JWT
def test_register_and_login_user():
    reg_response = client.post(
        "/users/",
        json={"email": "teste@livraria.com", "password": "senha123"},
    )
    assert reg_response.status_code == 201
    assert reg_response.json()["email"] == "teste@livraria.com"

    login_response = client.post(
        "/token",
        data={"username": "teste@livraria.com", "password": "senha123"},
    )
    assert login_response.status_code == 200
    assert "access_token" in login_response.json()
#--------------------------

# 6- testa a criação e a busca de um livro com usuário autenticado via Bearer Token
def test_create_and_get_book_authenticated():
    client.post("/users/", json={"email": "autor@livraria.com", "password": "123"})
    token_resp = client.post("/token", data={"username": "autor@livraria.com", "password": "123"})
    token = token_resp.json()["access_token"]

    headers = {"Authorization": f"Bearer {token}"}
    create_resp = client.post(
        "/books/",
        json={"name": "Dom Casmurro", "description": "Romance clássico", "price": 39.90},
        headers=headers,
    )
    assert create_resp.status_code == 201
    book_id = create_resp.json()["id"]

    get_resp = client.get(f"/books/{book_id}")
    assert get_resp.status_code == 200
    assert get_resp.json()["name"] == "Dom Casmurro"
#--------------------------
from datetime import timedelta
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

import auth
import models
import schemas
from database import get_db


tags_metadata = [
    {
        "name": "Geral",
        "description": "Rota inicial de verificação de status da API.",
    },
    {
        "name": "Autenticação & Usuários",
        "description": "Operações de cadastro de usuários, login e geração de tokens **JWT (OAuth2)**.",
    },
    {
        "name": "Livros",
        "description": "Operações CRUD para gerenciamento de livros.",
    },
]

app = FastAPI(
    title="Sistema de Livraria Online com Autenticação OAuth2 e JWT",
    description="API com CRUD de livros e controle de acesso via tokens JWT.",
    version="3.0.0",
    openapi_tags=tags_metadata,
)

#rota pública de boas-vindas
@app.get(
    "/",
    tags=["Geral"],
    summary="Rota inicial da API",
    response_description="Mensagem de boas-vindas da API",
)
async def root():
    """Rota pública inicial para verificar se a API da Livraria está online."""
    return {"Mensagem": "Sistema de Livraria Online com Autenticação OAuth2 e JWT"}


#rota para cadastrar um novo usuário (Pública)
@app.post(
    "/users/",
    response_model=schemas.UserResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Autenticação & Usuários"],
    summary="Cadastrar um novo usuário",
    response_description="Usuário cadastrado com sucesso",
    responses={
        400: {"description": "E-mail já cadastrado."},
    },
)
#--------------------------

async def register_user(user_data: schemas.UserCreate, db: Session = Depends(get_db),
):
    """ Rota para cadastrar um novo usuário, com senha criptografada e validação de e-mail único. 
    - **email**: e-mail do usuário (deve ser único)
    - **password**: senha do usuário (será armazenada de forma segura como hash)
    """
    #verifica se já existe um usuário com o mesmo e-mail (responsabilidade HTTP / validação de regra)
    db_user = auth.get_user_by_email(db, email=user_data.email)
    if db_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Já existe um usuário cadastrado com este e-mail.",
        )

    #cria o usuário (hash da senha + persistência no banco) através de função especializada
    return auth.create_user(db=db, user=user_data)
#--------------------------

#rota de login compatível com OAuth2 (utilizada pelo botão 'Authorize' do Swagger)
@app.post("/token", 
          response_model=schemas.Token,
          tags=["Autenticação & Usuários"],
          summary="Autenticar o user (OAuth2 / swagger)",
          response_description="Token JWT gerado com sucesso",
          responses={401: {"description": "E-mail ou senha incorretos."}},
          )
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    """Recebe o email, e password do usuário, autentica e retorna um token JWT válido para acesso às rotas protegidas."""
    user = auth.authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="E-mail ou senha incorretos.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token_expires = timedelta(minutes=auth.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = auth.create_access_token(
        data={"sub": user.email},
        expires_delta=access_token_expires,
    )

    return {"access_token": access_token, "token_type": "bearer"}
#--------------------------

#rota alternativa de login via JSON (/login)
@app.post("/login", 
          response_model=schemas.Token,
          tags=["Autenticação & Usuários"],
          summary="Login via JSON",
          response_description="Token JWT gerado com sucesso",
          responses={401: {"description": "E-mail ou senha incorretos."}},
          )
async def login_json(
    credentials: schemas.UserLogin, db: Session = Depends(get_db)):
    """Recebe o email, e password do usuário via JSON, autentica e retorna um token JWT válido para acesso às rotas protegidas."""
    user = auth.authenticate_user(db, credentials.email, credentials.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="E-mail ou senha incorretos.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token_expires = timedelta(minutes=auth.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = auth.create_access_token(
        data={"sub": user.email},
        expires_delta=access_token_expires,
    )

    return {"access_token": access_token, "token_type": "bearer"}
#--------------------------

#rota protegida para consultar os dados do usuário logado
@app.get("/users/me", 
        response_model=schemas.UserResponse,
        tags=["Autenticação & Usuários"],
        summary="Consultar dados do usuário logado",
        response_description="Dados do usuário logado",
        responses={401: {"description": "Token JWT inválido ou expirado."}},
         )
async def read_users_me(
    current_user: models.UserModel = Depends(auth.get_current_user)):
    """Rota protegida que retorna os dados do usuário logado, decodificando o token JWT e buscando o usuário no banco de dados."""
    return current_user
#--------------------------

#crud de livros (rotas protegidas e públicas)
#rtta protegida para cadastrar um novo livro (exige Bearer Token)
@app.post("/books/", 
          response_model=schemas.Book,
          status_code=status.HTTP_201_CREATED,
          summary="Cadastrar um novo livro (rota protegida)",
          response_description="Livro cadastrado com sucesso",
          tags=["Livros"],
          responses={
                400: {"description": "Livro com este ID já existe."},
                401: {"description": "Token JWT inválido ou expirado."},
            }
          )
async def create_book(book: schemas.BookCreate, db: Session = Depends(get_db), current_user: models.UserModel = Depends(auth.get_current_user)):
    """Rota protegida para cadastrar um novo livro. Exige autenticação via token JWT (Bearer Token)."""
    if book.id is not None:
        existing_book = db.query(models.BookModel).filter(models.BookModel.id == book.id).first()
        if existing_book:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Livro com este ID já existe.",
            )

    db_book = models.BookModel(
        id=book.id,
        name=book.name,
        description=book.description,
        price=book.price,
    )

    db.add(db_book)
    db.commit()
    db.refresh(db_book)

    return db_book
#--------------------------

#rota publica para listar todos os livros
@app.get(
    "/books/",
    response_model=list[schemas.Book],
    tags=["Livros"],
    summary="Listar todos os livros",
    response_description="Lista de todos os livros cadastrados",
)
async def get_all_books(db: Session = Depends(get_db)):
    """Rota pública que retorna todos os livros cadastrados no banco de dados."""
    return db.query(models.BookModel).all()


#rota publica para buscar um livro específico pelo ID
@app.get(
    "/books/{book_id}",
    response_model=schemas.Book,
    tags=["Livros"],
    summary="Buscar um livro pelo ID",
    response_description="Dados detalhados do livro encontrado",
    responses={
        404: {"description": "Livro não encontrado no banco de dados."},
    },
)
async def get_book(book_id: int, db: Session = Depends(get_db)):
    """
    Busca e retorna os detalhes de um livro específico a partir do seu **ID**.

    - **book_id**: Identificador numérico único do livro.
    """
    book = db.query(models.BookModel).filter(models.BookModel.id == book_id).first()
    if not book:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Livro não encontrado.")
    return book
#--------------------------

#rota protegida para deletar um livro pelo ID (exige Bearer Token)
@app.delete("/books/{book_id}", 
            status_code=status.HTTP_204_NO_CONTENT,
            summary="Deletar um livro pelo ID (rota protegida)", 
            response_description="Livro deletado com sucesso",
            tags=["Livros"],
            responses={
                401: {"description": "Token JWT inválido ou expirado."},
                404: {"description": "Livro não encontrado no banco de dados."},
            }
            )
async def delete_book(book_id: int, db: Session = Depends(get_db), current_user: models.UserModel = Depends(auth.get_current_user)):
    """Rota protegida para deletar um livro pelo ID. Exige autenticação via token JWT (Bearer Token)."""
    book = db.query(models.BookModel).filter(models.BookModel.id == book_id).first()
    if not book:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Livro não encontrado.")
    
    db.delete(book)
    db.commit()
    return
#--------------------------

#rota protegida para atualizar um livro pelo ID (exige Bearer Token)
@app.put("/books/{book_id}", 
         response_model=schemas.Book,
         summary="Atualizar um livro pelo ID (rota protegida)",
            response_description="Livro atualizado com sucesso",
            tags=["Livros"],
            responses={
                401: {"description": "Token JWT inválido ou expirado."},
                404: {"description": "Livro não encontrado no banco de dados."},
            }
)
async def update_book(book_id: int, updated_book: schemas.BookUpdate, db: Session = Depends(get_db), current_user: models.UserModel = Depends(auth.get_current_user)):
    """Rota protegida para atualizar um livro pelo ID. Exige autenticação via token JWT (Bearer Token)."""
    book = db.query(models.BookModel).filter(models.BookModel.id == book_id).first()
    if not book:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Livro não encontrado.")

    book.name = updated_book.name
    book.description = updated_book.description
    book.price = updated_book.price

    db.commit()
    db.refresh(book)
    return book
#--------------------------
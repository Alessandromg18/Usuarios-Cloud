import boto3
import hashlib
import uuid
import os
from datetime import datetime, timedelta

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def login_user(event, context):
    print("Evento login:", event)

    try:
        # ============================
        # Obtener body
        # ============================
        body = event.get("body")
        if isinstance(body, str):
            import json
            body = json.loads(body)

        tenant_id = body.get("tenant_id")
        password = body.get("password")

        if not tenant_id or not password:
            return {
                "statusCode": 400,
                "body": {"error": "Faltan tenant_id o password"}
            }

        # ============================
        # DynamoDB
        # ============================
        dynamodb = boto3.resource("dynamodb")
        users_table = dynamodb.Table(os.environ["DYNAMODB_TABLE_T_USERS"])
        tokens_table = dynamodb.Table(os.environ["DYNAMODB_TABLE_T_TOKENS"])

        # ============================
        # Buscar usuario por tenant_id
        # ============================
        response = users_table.query(
            KeyConditionExpression=boto3.dynamodb.conditions.Key("tenant_id").eq(tenant_id)
        )

        if "Items" not in response or len(response["Items"]) == 0:
            return {
                "statusCode": 403,
                "body": {"error": "Usuario no existe"}
            }

        # Solo hay un usuario por tenant_id
        user = response["Items"][0]
        hashed_password_db = user["contraseña"]

        # ============================
        # Validar contraseña
        # ============================
        if hashed_password_db != hash_password(password):
            return {
                "statusCode": 403,
                "body": {"error": "Contraseña incorrecta"}
            }

        # ============================
        # Crear token válido 12 horas
        # ============================
        token = str(uuid.uuid4())        # será PK en t-tokens
        token_id = str(uuid.uuid4())     # será SK en t-tokens
        expiration_time = datetime.now() + timedelta(hours=12)

        token_data = {
            "tenant_id": token,                      # PK = token
            "token_id": token_id,                    # SK = token_id
            "user_uuid": user["uuid"],               # UUID del usuario
            "usuario_tenant_id": user["tenant_id"],  # <-- NECESARIO PARA get_user_profile
            "estado": user.get("estado", "friendzone"),
            "token": token,
            "fecha_creacion": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "expires": expiration_time.strftime("%Y-%m-%d %H:%M:%S")
        }

        # Guardar token
        tokens_table.put_item(Item=token_data)

        # ============================
        # Respuesta
        # ============================
        return {
            "statusCode": 200,
            "body": {
                "message": "Login exitoso",
                "token": token,
                "estado": user.get("estado", "friendzone"),
                "uuid": user["uuid"]
            }
        }

    except Exception as e:
        print("ERROR LOGIN:", str(e))
        return {
            "statusCode": 500,
            "body": {"error": str(e)}
        }

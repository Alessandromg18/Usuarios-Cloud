import boto3
import os
from datetime import datetime

def validate_token(event, context):
    print("Evento recibido en validate_token:", event)

    try:
        # ===============================
        # Obtener token del header
        # ===============================
        auth_header = event.get("headers", {}).get("Authorization")

        if not auth_header or not auth_header.startswith("Bearer "):
            return {
                "statusCode": 400,
                "body": {"error": "Falta el token en los headers (Bearer <token>)"}
            }

        token = auth_header.replace("Bearer ", "").strip()

        # ===============================
        # DynamoDB
        # ===============================
        dynamodb = boto3.resource("dynamodb")
        tokens_table = dynamodb.Table(os.environ["DYNAMODB_TABLE_T_TOKENS"])

        # ===============================
        # Buscar el token
        # PK = token
        # ===============================
        response = tokens_table.query(
            KeyConditionExpression=boto3.dynamodb.conditions.Key("tenant_id").eq(token)
        )

        if "Items" not in response or len(response["Items"]) == 0:
            return {
                "statusCode": 403,
                "body": {"error": "Token no válido o no encontrado"}
            }

        token_item = response["Items"][0]

        # ===============================
        # Validar expiración
        # ===============================
        expires = token_item["expires"]
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        if now > expires:
            return {
                "statusCode": 403,
                "body": {"error": "Token expirado"}
            }

        # ===============================
        # Respuesta si el token es válido
        # ===============================
        return {
            "statusCode": 200,
            "body": {
                "message": "Token válido",
                "user_uuid": token_item.get("user_uuid"),
                "estado": token_item.get("estado"),
                "expires": expires
            }
        }

    except Exception as e:
        print("ERROR validate_token:", str(e))
        return {
            "statusCode": 500,
            "body": {"error": str(e)}
        }

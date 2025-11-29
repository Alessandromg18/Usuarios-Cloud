import boto3
import os
from datetime import datetime

def get_user_profile(event, context):
    print("Evento en get_user_profile:", event)

    try:
        # ===============================
        # 1. Obtener token del header
        # ===============================
        auth_header = event.get("headers", {}).get("Authorization")

        if not auth_header or not auth_header.startswith("Bearer "):
            return {
                "statusCode": 400,
                "body": {"error": "Falta el token en los headers"}
            }

        token = auth_header.replace("Bearer ", "").strip()

        # ===============================
        # 2. Buscar token en DynamoDB
        # ===============================
        dynamodb = boto3.resource("dynamodb")
        tokens_table = dynamodb.Table(os.environ["DYNAMODB_TABLE_T_TOKENS"])
        users_table = dynamodb.Table(os.environ["DYNAMODB_TABLE_T_USERS"])

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
        # 3. Validar expiración
        # ===============================
        expires = token_item["expires"]
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if now > expires:
            return {
                "statusCode": 403,
                "body": {"error": "Token expirado"}
            }

        # ===============================
        # 4. Obtener datos del usuario
        # ===============================
        tenant_id_usuario = token_item["usuario_tenant_id"]
        user_uuid = token_item["user_uuid"]

        user_response = users_table.get_item(
            Key={
                "tenant_id": tenant_id_usuario,
                "uuid": user_uuid
            }
        )

        if "Item" not in user_response:
            return {
                "statusCode": 404,
                "body": {"error": "Usuario no encontrado"}
            }

        user = user_response["Item"]

        # ===============================
        # 5. Eliminar contraseña antes de enviar
        # ===============================
        if "contraseña" in user:
            del user["contraseña"]

        return {
            "statusCode": 200,
            "body": {
                "message": "Perfil obtenido correctamente",
                "perfil": user
            }
        }

    except Exception as e:
        print("ERROR get_user_profile:", str(e))
        return {
            "statusCode": 500,
            "body": {"error": str(e)}
        }

import boto3
import os
import json
from datetime import datetime

def add_favorito(event, context):
    print("Evento en add_favorito:", event)

    try:
        # ===============================
        # Validar token
        # ===============================
        auth_header = event.get("headers", {}).get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return {"statusCode": 400, "body": {"error": "Falta token"}}

        token = auth_header.replace("Bearer ", "").strip()

        dynamodb = boto3.resource("dynamodb")
        tokens_table = dynamodb.Table(os.environ["DYNAMODB_TABLE_T_TOKENS"])
        users_table = dynamodb.Table(os.environ["DYNAMODB_TABLE_T_USERS"])

        token_resp = tokens_table.query(
            KeyConditionExpression=boto3.dynamodb.conditions.Key("tenant_id").eq(token)
        )

        if "Items" not in token_resp or len(token_resp["Items"]) == 0:
            return {"statusCode": 403, "body": {"error": "Token inválido"}}

        token_item = token_resp["Items"][0]

        if datetime.now().strftime("%Y-%m-%d %H:%M:%S") > token_item["expires"]:
            return {"statusCode": 403, "body": {"error": "Token expirado"}}

        tenant_id = token_item["usuario_tenant_id"]
        user_uuid = token_item["user_uuid"]

        # ===============================
        # Body
        # ===============================
        body = event.get("body")
        if isinstance(body, str):
            body = json.loads(body)

        favorito = {
            "nombre": body.get("nombre"),
            "descripcion": body.get("descripcion"),
            "precio": body.get("precio")
        }

        if not favorito["nombre"]:
            return {"statusCode": 400, "body": {"error": "Falta nombre del favorito"}}

        users_table.update_item(
            Key={"tenant_id": tenant_id, "uuid": user_uuid},
            UpdateExpression="SET mis_favoritos = list_append(mis_favoritos, :f)",
            ExpressionAttributeValues={":f": [favorito]}
        )

        return {"statusCode": 200, "body": {"message": "Favorito agregado"}}

    except Exception as e:
        print("ERROR add_favorito:", str(e))
        return {"statusCode": 500, "body": {"error": str(e)}}

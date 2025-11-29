import boto3
import os
import json
from datetime import datetime

def update_user(event, context):
    print("Evento en update_user:", event)

    try:
        # ===============================
        # 1. Obtener token del header
        # ===============================
        auth_header = event.get("headers", {}).get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return {"statusCode": 400, "body": {"error": "Falta el token"}}

        token = auth_header.replace("Bearer ", "").strip()

        # ===============================
        # 2. Buscar token en DynamoDB
        # ===============================
        dynamodb = boto3.resource("dynamodb")
        tokens_table = dynamodb.Table(os.environ["DYNAMODB_TABLE_T_TOKENS"])
        users_table = dynamodb.Table(os.environ["DYNAMODB_TABLE_T_USERS"])

        token_response = tokens_table.query(
            KeyConditionExpression=boto3.dynamodb.conditions.Key("tenant_id").eq(token)
        )

        if "Items" not in token_response or len(token_response["Items"]) == 0:
            return {"statusCode": 403, "body": {"error": "Token no válido"}}

        token_item = token_response["Items"][0]

        # Validar expiración
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if now > token_item["expires"]:
            return {"statusCode": 403, "body": {"error": "Token expirado"}}

        tenant_id = token_item["usuario_tenant_id"]
        user_uuid = token_item["user_uuid"]

        # ===============================
        # 3. Obtener campos del body
        # ===============================
        body = event.get("body")
        if isinstance(body, str):
            body = json.loads(body)

        # Campos permitidos para editar
        editable = [
            "nombre", "apellidos", "tipo_documento", "documento",
            "numero", "fecha_nacimiento", "mi_direccion",
            "direccion_de_facturacion",
            "puntos_de_amor", "estado", "multiplicador_de_puntos"
        ]

        update_expr = []
        expr_vals = {}

        for field in editable:
            if field in body:
                update_expr.append(f"{field} = :{field}")
                expr_vals[f":{field}"] = body[field]

        if not update_expr:
            return {"statusCode": 400, "body": {"error": "No se enviaron campos válidos"}}

        # ===============================
        # 4. Ejecutar UPDATE
        # ===============================
        users_table.update_item(
            Key={"tenant_id": tenant_id, "uuid": user_uuid},
            UpdateExpression="SET " + ", ".join(update_expr),
            ExpressionAttributeValues=expr_vals
        )

        return {"statusCode": 200, "body": {"message": "Datos actualizados correctamente"}}

    except Exception as e:
        print("ERROR update_user:", str(e))
        return {"statusCode": 500, "body": {"error": str(e)}}
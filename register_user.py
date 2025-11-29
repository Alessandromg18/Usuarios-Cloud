import boto3
import hashlib
import uuid
import os
from datetime import datetime

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def register_user(event, context):
    print("Evento recibido:", event)

    try:
        body = event.get("body")
        if isinstance(body, str):
            import json
            body = json.loads(body)

        # Campos obligatorios
        nombre = body.get("nombre")
        apellidos = body.get("apellidos")
        tipo_documento = body.get("tipo_documento")
        documento = body.get("documento")
        numero = body.get("numero")
        fecha_nacimiento = body.get("fecha_nacimiento")
        tenant_id = body.get("tenant_id")  # correo
        password = body.get("password")

        # Validación de campos requeridos
        if not all([
            nombre, apellidos, tipo_documento, documento,
            numero, fecha_nacimiento, tenant_id, password
        ]):
            return {
                "statusCode": 400,
                "body": {"error": "Faltan datos obligatorios en el registro"}
            }

        # Hash de contraseña
        hashed_password = hash_password(password)

        # UUID (sort key)
        user_uuid = str(uuid.uuid4())

        fecha_registro = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # DynamoDB
        dynamodb = boto3.resource("dynamodb")
        users_table = dynamodb.Table(os.environ["DYNAMODB_TABLE_T_USERS"])

        # Objeto final con tu estructura
        user_item = {
            "tenant_id": tenant_id,     # Partition Key
            "uuid": user_uuid,          # Sort Key

            "nombre": nombre,
            "apellidos": apellidos,
            "tipo_documento": tipo_documento,
            "documento": documento,
            "numero": numero,
            "fecha_nacimiento": fecha_nacimiento,

            "contraseña": hashed_password,

            # estos se completan vacíos por ahora
            "mi_direccion": "",
            "direccion_de_facturacion": "",

            # valores por defecto
            "puntos_de_amor": 0,
            "estado": "friendzone",
            "multiplicador_de_puntos": 1,
            "beneficios": {},
            "mis_favoritos": [],

            "fecha_registro": fecha_registro
        }

        # Guardar en DynamoDB
        users_table.put_item(Item=user_item)

        return {
            "statusCode": 200,
            "body": {
                "message": "Usuario creado exitosamente",
                "uuid": user_uuid
            }
        }

    except Exception as e:
        print("ERROR:", str(e))
        return {
            "statusCode": 500,
            "body": {"error": str(e)}
        }

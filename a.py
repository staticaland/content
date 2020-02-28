from bravado.client import SwaggerClient


if __name__ == "__main__":
    client = SwaggerClient.from_url(
        'http://petstore.swagger.io/v2/swagger.json',
        config={'use_models': False}
    )

    result = client.pet.getPetById(petId=42).result(timeout=4)
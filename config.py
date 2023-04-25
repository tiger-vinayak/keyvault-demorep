from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient



def get_secret(name):
    credential = DefaultAzureCredential()
    secret_client = SecretClient(vault_url="https://keyvaultdemo51.vault.azure.net/", credential=credential)
    secret = secret_client.get_secret(name)
    print(secret.name)
    print(secret.value)
    return secret.value

# Vault Certificate OpenSSH

This script check your current certificate expiration and ask to sign on your vault if needed

## Usage

### Vault

On your vault server you need to follow this documentation: https://www.vaultproject.io/docs/secrets/ssh/signed-ssh-certificates.html

### SSH Wrapper

Before each SSH connection add this wrapper command: 
```bash
python vault-cert-openssh.py ~/.ssh/<your SSH key>-cert.pub
```

# Dev side

Prerequisite:
* Python >=3.7
 * hvac
* Vault
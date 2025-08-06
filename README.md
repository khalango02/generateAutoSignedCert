# Como usar o script gerar_certificado.py

## Instalação de dependências
Primeiro, instale a biblioteca necessária:

```bash
pip install cryptography
```

## Exemplos de uso

### Exemplo básico (apenas Common Name)
```bash
python gerar_certificado.py --common-name "exemplo.com"
```

### Exemplo completo com todos os campos do subject
```bash
python gerar_certificado.py \
  --country "BR" \
  --state "São Paulo" \
  --locality "São Paulo" \
  --organization "Minha Empresa Ltda" \
  --organizational-unit "TI" \
  --common-name "api.minhaempresa.com.br" \
  --email "admin@minhaempresa.com.br"
```

### Exemplo com configurações personalizadas
```bash
python gerar_certificado.py \
  --common-name "servidor.local" \
  --key-size 4096 \
  --validity-days 730 \
  --key-password "minhasenha123" \
  --cert-file "meu_certificado.pem" \
  --key-file "minha_chave.pem"
```

## Parâmetros disponíveis

### Subject (Identificação do certificado)
- `--country` ou `-c`: Código do país (2 letras, ex: BR)
- `--state` ou `-s`: Estado ou província
- `--locality` ou `-l`: Cidade
- `--organization` ou `-o`: Nome da organização
- `--organizational-unit` ou `-ou`: Unidade organizacional
- `--common-name` ou `-cn`: Nome comum (OBRIGATÓRIO)
- `--email` ou `-e`: Endereço de email

### Configurações técnicas
- `--key-size`: Tamanho da chave em bits (padrão: 2048)
- `--validity-days`: Validade em dias (padrão: 365)
- `--key-password`: Senha para criptografar a chave privada

### Arquivos de saída
- `--cert-file`: Nome do arquivo do certificado (padrão: certificado.pem)
- `--key-file`: Nome do arquivo da chave privada (padrão: chave_privada.pem)

## Verificação do certificado gerado

Para verificar o certificado gerado, você pode usar o OpenSSL:

```bash
# Visualizar detalhes do certificado
openssl x509 -in certificado.pem -text -noout

# Verificar se a chave privada corresponde ao certificado
openssl x509 -noout -modulus -in certificado.pem | openssl md5
openssl rsa -noout -modulus -in chave_privada.pem | openssl md5
```

## Notas importantes

1. O certificado gerado será autoassinado, ou seja, não será confiável por padrão nos navegadores
2. Para uso em produção, considere usar certificados de uma Autoridade Certificadora (CA) confiável
3. Mantenha a chave privada segura e nunca a compartilhe
4. Use senhas fortes para proteger a chave privada quando necessário

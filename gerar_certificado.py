import os
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import argparse


def gerar_chave_privada(tamanho_chave=2048):
    
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=tamanho_chave,
    )

def criar_subject(country=None, state=None, locality=None, organization=None, 
                 organizational_unit=None, common_name=None, email=None):
    
    subject_components = []
    
    if country:
        subject_components.append(x509.NameAttribute(NameOID.COUNTRY_NAME, country))
    if state:
        subject_components.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state))
    if locality:
        subject_components.append(x509.NameAttribute(NameOID.LOCALITY_NAME, locality))
    if organization:
        subject_components.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization))
    if organizational_unit:
        subject_components.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, organizational_unit))
    if common_name:
        subject_components.append(x509.NameAttribute(NameOID.COMMON_NAME, common_name))
    if email:
        subject_components.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, email))
    
    return x509.Name(subject_components)


def gerar_certificado_autoassinado(chave_privada, subject, validade_dias=365, 
                                  algoritmo_hash=hashes.SHA256()):
    
    issuer = subject
    
    data_inicio = datetime.now(timezone.utc)
    data_fim = data_inicio + timedelta(days=validade_dias)
    
    certificado = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        chave_privada.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        data_inicio
    ).not_valid_after(
        data_fim
    ).add_extension(
        x509.SubjectAlternativeName([]),
        critical=False,
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True,
    ).add_extension(
        x509.KeyUsage(
            key_cert_sign=True,
            crl_sign=True,
            digital_signature=True,
            key_encipherment=True,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    ).sign(chave_privada, algoritmo_hash)
    
    return certificado


def salvar_chave_privada(chave_privada, caminho_arquivo, senha=None):
    
    encryption_algorithm = serialization.NoEncryption()
    if senha:
        encryption_algorithm = serialization.BestAvailableEncryption(senha.encode())
    
    with open(caminho_arquivo, "wb") as f:
        f.write(chave_privada.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm,
        ))


def salvar_certificado(certificado, caminho_arquivo):
    
    with open(caminho_arquivo, "wb") as f:
        f.write(certificado.public_bytes(serialization.Encoding.PEM))


def main():
    parser = argparse.ArgumentParser(description='Gera certificado autoassinado com subject customizado')
    
    parser.add_argument('--country', '-c', help='Código do país (2 letras, ex: BR)')
    parser.add_argument('--state', '-s', help='Estado ou província')
    parser.add_argument('--locality', '-l', help='Cidade')
    parser.add_argument('--organization', '-o', help='Nome da organização')
    parser.add_argument('--organizational-unit', '-ou', help='Unidade organizacional')
    parser.add_argument('--common-name', '-cn', required=True, help='Nome comum (obrigatório)')
    parser.add_argument('--email', '-e', help='Endereço de email')
    
    parser.add_argument('--key-size', type=int, default=2048, help='Tamanho da chave em bits (padrão: 2048)')
    parser.add_argument('--validity-days', type=int, default=365, help='Validade em dias (padrão: 365)')
    parser.add_argument('--key-password', help='Senha para criptografar a chave privada')
    
    parser.add_argument('--cert-file', default='certificado.pem', help='Nome do arquivo do certificado (padrão: certificado.pem)')
    parser.add_argument('--key-file', default='chave_privada.pem', help='Nome do arquivo da chave privada (padrão: chave_privada.pem)')
    
    args = parser.parse_args()
    
    try:
        print("🔐 Gerando certificado autoassinado...")
        print(f"📋 Common Name: {args.common_name}")
        
        print("🔑 Gerando chave privada...")
        chave_privada = gerar_chave_privada(args.key_size)
        
        subject = criar_subject(
            country=args.country,
            state=args.state,
            locality=args.locality,
            organization=args.organization,
            organizational_unit=args.organizational_unit,
            common_name=args.common_name,
            email=args.email
        )
        
        print("📜 Gerando certificado...")
        certificado = gerar_certificado_autoassinado(
            chave_privada=chave_privada,
            subject=subject,
            validade_dias=args.validity_days
        )
        
        print(f"💾 Salvando chave privada em: {args.key_file}")
        salvar_chave_privada(chave_privada, args.key_file, args.key_password)
        
        print(f"💾 Salvando certificado em: {args.cert_file}")
        salvar_certificado(certificado, args.cert_file)
        
        print("✅ Certificado gerado com sucesso!")
        print(f"📄 Certificado: {args.cert_file}")
        print(f"🔐 Chave privada: {args.key_file}")
        print(f"⏰ Válido por: {args.validity_days} dias")
        
        print("\n📋 Informações do certificado:")
        print(f"   Subject: {certificado.subject.rfc4514_string()}")
        print(f"   Serial Number: {certificado.serial_number}")
        print(f"   Válido de: {certificado.not_valid_before_utc}")
        print(f"   Válido até: {certificado.not_valid_after_utc}")
        
    except Exception as e:
        print(f"❌ Erro ao gerar certificado: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())

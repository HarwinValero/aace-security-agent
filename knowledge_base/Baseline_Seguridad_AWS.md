# Baseline de Seguridad AWS - Estándares Corporativos

## 🎯 Objetivo

Esta baseline define los controles de seguridad obligatorios para todas las cuentas AWS de la organización, mapeados a los marcos CIS AWS Benchmark v3.0, SOC 2 TSC, y AWS Well-Architected Framework.

---

## 📋 Controles Críticos (Nivel 1)

### 1. **WAF (Web Application Firewall)**

**Control ID:** SEC-WAF-001  
**Marco:** CIS AWS 2.4 | SOC 2 CC7.1  
**Severidad:** CRÍTICA

#### Requisitos:
- ✅ WAF habilitado en TODOS los ALBs con endpoints públicos
- ✅ WAF habilitado en TODAS las distribuciones CloudFront
- ✅ Mínimo 3 rule groups activos:
  - AWS Managed Rules: Core Rule Set (CRS)
  - AWS Managed Rules: Known Bad Inputs
  - AWS Managed Rules: SQL Database
- ✅ Rate limiting: 2000 requests/5min por IP (ajustable según tráfico)
- ✅ Logging habilitado hacia S3 o CloudWatch Logs

#### Evidencias a recolectar:
```bash
aws wafv2 list-web-acls --scope REGIONAL
aws wafv2 list-resources-for-web-acl --web-acl-arn <ARN> --resource-type APPLICATION_LOAD_BALANCER
aws wafv2 get-logging-configuration --resource-arn <ARN>
```

#### Remediation:
- Crear WebACL desde plantilla corporativa
- Asociar a recursos desprotegidos
- Habilitar logging

---

### 2. **IAM - Gestión de Identidades**

**Control ID:** SEC-IAM-001 a SEC-IAM-005  
**Marco:** CIS AWS 1.12, 1.16 | SOC 2 CC6.1, CC6.2, CC6.3  
**Severidad:** CRÍTICA

#### Requisitos:

##### SEC-IAM-001: MFA Obligatorio
- ✅ MFA habilitado para TODOS los usuarios IAM
- ✅ MFA habilitado en cuenta root
- ✅ Política SCP a nivel Organizations forzando MFA

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Deny",
    "Action": "*",
    "Resource": "*",
    "Condition": {
      "BoolIfExists": {"aws:MultiFactorAuthPresent": "false"}
    }
  }]
}
```

##### SEC-IAM-002: Rotación de Llaves
- ✅ Access Keys rotadas cada **90 días máximo**
- ✅ Llaves inactivas > 90 días deshabilitadas automáticamente
- ✅ Alertas automáticas a propietarios a los 75 días

##### SEC-IAM-003: Principio de Mínimo Privilegio
- ❌ PROHIBIDO: Políticas con `"Action": "*"` o `"Resource": "*"` juntas
- ✅ Usar roles de sesión en lugar de usuarios permanentes
- ✅ Session duration: 4 horas máximo

##### SEC-IAM-004: Sin Usuarios Administrativos
- ❌ PROHIBIDO: Usuarios IAM con `AdministratorAccess` attached directamente
- ✅ Usar AWS SSO / Identity Center con asignaciones temporales
- ✅ Roles administrativos con MFA y logging detallado

##### SEC-IAM-005: Password Policy
- ✅ Mínimo 14 caracteres
- ✅ Requiere mayúsculas, minúsculas, números, símbolos
- ✅ Expiración: 90 días
- ✅ Prevenir reutilización: últimas 5 contraseñas

#### Evidencias:
```bash
aws iam get-credential-report
aws iam list-users
aws iam list-access-keys --user-name <USER>
aws iam get-account-password-policy
```

---

### 3. **S3 - Almacenamiento Seguro**

**Control ID:** SEC-S3-001 a SEC-S3-004  
**Marco:** CIS AWS 3.1, 3.3 | SOC 2 CC6.1  
**Severidad:** CRÍTICA

#### Requisitos:

##### SEC-S3-001: Block Public Access
- ✅ Block Public Access habilitado a nivel de cuenta (Organizations)
- ✅ Block Public Access habilitado en CADA bucket
- ⚠️ Excepciones: Solo buckets de sitios web estáticos (requieren aprobación)

##### SEC-S3-002: Cifrado en Reposo
- ✅ Default encryption habilitado en TODOS los buckets
- ✅ Usar AWS KMS (preferido) o SSE-S3
- ✅ Política de bucket denegando uploads sin cifrado:

```json
{
  "Effect": "Deny",
  "Action": "s3:PutObject",
  "Condition": {
    "StringNotEquals": {
      "s3:x-amz-server-side-encryption": ["AES256", "aws:kms"]
    }
  }
}
```

##### SEC-S3-003: Versionado y Lifecycle
- ✅ Versionado habilitado en buckets con datos críticos
- ✅ Lifecycle policies para transicionar a Glacier > 90 días
- ✅ MFA Delete habilitado en buckets de compliance

##### SEC-S3-004: Logging
- ✅ Server access logging habilitado
- ✅ Logs centralizados en bucket dedicado con acceso restringido

---

### 4. **Logging y Monitoreo**

**Control ID:** SEC-LOG-001 a SEC-LOG-004  
**Marco:** CIS AWS 3.2, 3.4 | SOC 2 CC7.2  
**Severidad:** CRÍTICA

#### Requisitos:

##### SEC-LOG-001: CloudTrail
- ✅ CloudTrail a nivel Organizations habilitado
- ✅ Logging de eventos de management + data events (S3, Lambda)
- ✅ Log file validation habilitado
- ✅ Cifrado con KMS
- ✅ Retención: **mínimo 1 año**

##### SEC-LOG-002: VPC Flow Logs
- ✅ Habilitado en TODAS las VPCs
- ✅ Log rejected + accepted traffic
- ✅ Almacenamiento en S3 o CloudWatch Logs

##### SEC-LOG-003: GuardDuty
- ✅ Habilitado en TODAS las cuentas
- ✅ Configurado a nivel Organizations (delegated admin)
- ✅ Findings de severidad HIGH/CRITICAL → alerta inmediata (SNS/Lambda)

##### SEC-LOG-004: Security Hub
- ✅ Habilitado en cuenta de seguridad centralizada
- ✅ Integración con: GuardDuty, Inspector, Macie, Config
- ✅ Standards habilitados: CIS AWS Foundations, AWS Foundational Security Best Practices

---

### 5. **Cifrado en Reposo y Tránsito**

**Control ID:** SEC-ENC-001 a SEC-ENC-003  
**Marco:** CIS AWS 2.8 | SOC 2 CC6.1  
**Severidad:** CRÍTICA

#### Requisitos:

##### SEC-ENC-001: KMS
- ✅ Customer Managed Keys (CMKs) para datos sensibles
- ✅ Key rotation automática habilitada (anual)
- ✅ Key policies con principio de mínimo privilegio

##### SEC-ENC-002: EBS/RDS
- ✅ Cifrado en reposo obligatorio para:
  - Volúmenes EBS (incluidos snapshots)
  - Instancias RDS
  - Clusters Aurora
  - Volúmenes EFS
- ✅ Default encryption habilitado a nivel de cuenta

##### SEC-ENC-003: Tránsito (SSL/TLS)
- ✅ ALB Listeners: Solo HTTPS (puerto 443)
- ✅ HTTP (puerto 80): Solo redirect a HTTPS
- ✅ TLS 1.2+ obligatorio (deshabilitar TLS 1.0/1.1)
- ✅ Certificados ACM (renovación automática)

#### Evidencias:
```bash
aws kms list-keys
aws kms describe-key --key-id <KEY_ID>
aws ec2 get-ebs-encryption-by-default
aws rds describe-db-instances --query 'DBInstances[?StorageEncrypted==`false`]'
```

---

### 6. **Network Security**

**Control ID:** SEC-NET-001 a SEC-NET-003  
**Marco:** CIS AWS 5.1, 5.2 | SOC 2 CC6.1  
**Severidad:** ALTA

#### Requisitos:

##### SEC-NET-001: Security Groups
- ❌ PROHIBIDO: Reglas con `0.0.0.0/0` en puertos críticos:
  - 22 (SSH)
  - 3389 (RDP)
  - 5432 (PostgreSQL)
  - 3306 (MySQL)
  - 1433 (MSSQL)
- ✅ Usar Security Groups como origen/destino (no IPs)
- ✅ Descripción obligatoria en cada regla

##### SEC-NET-002: Network ACLs
- ✅ Default DENY en NACLs de subnets públicas
- ✅ Permitir solo puertos necesarios
- ✅ Logging habilitado (VPC Flow Logs)

##### SEC-NET-003: VPC
- ✅ VPC dedicadas por entorno (prod/staging/dev)
- ✅ Subnets privadas para workloads (sin route a IGW)
- ✅ NAT Gateway para salida de subnets privadas
- ✅ VPC Endpoints para servicios AWS (S3, DynamoDB)

---

### 7. **EC2 y Compute**

**Control ID:** SEC-EC2-001 a SEC-EC2-003  
**Marco:** AWS Well-Architected - Security Pillar  
**Severidad:** ALTA

#### Requisitos:

##### SEC-EC2-001: Parches y Actualizaciones
- ✅ AWS Systems Manager Patch Manager configurado
- ✅ Parches críticos aplicados en < 7 días
- ✅ Scanning de vulnerabilidades con Inspector

##### SEC-EC2-002: Metadata Service (IMDS)
- ✅ IMDSv2 obligatorio (deshabilitar IMDSv1)
- ✅ Configurar en launch templates:

```json
{
  "MetadataOptions": {
    "HttpTokens": "required",
    "HttpPutResponseHopLimit": 1
  }
}
```

##### SEC-EC2-003: SSH/RDP
- ❌ PROHIBIDO: Llaves SSH compartidas
- ✅ Usar AWS Systems Manager Session Manager (sin abrir puerto 22)
- ✅ Bastion hosts en subnet pública (con MFA y logging)

---

## 📊 Matriz de Cumplimiento

| Control | CIS AWS | SOC 2 | Well-Architected | Severidad | Automatizable |
|---------|---------|-------|------------------|-----------|---------------|
| SEC-WAF-001 | 2.4 | CC7.1 | Security | CRÍTICA | ✅ Sí |
| SEC-IAM-001 | 1.2 | CC6.2 | Security | CRÍTICA | ✅ Sí (SCP) |
| SEC-IAM-002 | 1.12 | CC6.2 | Security | CRÍTICA | ✅ Sí (Lambda) |
| SEC-IAM-003 | 1.16 | CC6.3 | Security | CRÍTICA | ⚠️ Parcial |
| SEC-S3-001 | 3.1 | CC6.1 | Security | CRÍTICA | ✅ Sí (SCP) |
| SEC-S3-002 | 3.3 | CC6.1 | Security | CRÍTICA | ✅ Sí (Config Rule) |
| SEC-LOG-001 | 3.2 | CC7.2 | Reliability | CRÍTICA | ✅ Sí (CFN) |
| SEC-LOG-002 | 3.9 | CC7.2 | Security | ALTA | ✅ Sí (CFN) |
| SEC-LOG-003 | - | CC7.1 | Security | ALTA | ✅ Sí (API) |
| SEC-ENC-001 | 2.8 | CC6.1 | Security | CRÍTICA | ✅ Sí (Config Rule) |
| SEC-ENC-002 | 2.8 | CC6.1 | Security | CRÍTICA | ✅ Sí (SCP) |
| SEC-NET-001 | 5.1 | CC6.1 | Security | ALTA | ✅ Sí (Config Rule) |

---

## 🔄 Proceso de Auditoría

### Frecuencia
- **Semanal:** Auditorías automatizadas (AEGIS Agent)
- **Mensual:** Revisión de compliance por cuenta
- **Trimestral:** Revisión de baseline (actualizaciones)

### Roles y Responsabilidades
- **Security Team:** Mantiene baseline, ejecuta auditorías, investiga incidentes
- **DevOps Teams:** Implementan controles, remedian hallazgos
- **Compliance Officer:** Valida evidencias para auditorías externas

### Escalamiento
- **CRÍTICO:** Remediar en < 24 horas
- **ALTO:** Remediar en < 7 días
- **MEDIO:** Remediar en < 30 días
- **BAJO:** Remediar en siguiente sprint

---

## 🛠️ Herramientas de Validación

### Comandos AWS CLI

#### Validar WAF
```bash
# Listar WebACLs
aws wafv2 list-web-acls --scope REGIONAL

# Verificar recursos asociados
aws wafv2 list-resources-for-web-acl \
  --web-acl-arn <ARN> \
  --resource-type APPLICATION_LOAD_BALANCER
```

#### Validar IAM
```bash
# Usuarios sin MFA
aws iam get-credential-report | \
  jq -r '.Content | @base64d' | \
  csvcut -c user,mfa_active | \
  grep false

# Llaves antiguas
aws iam list-users --query 'Users[].UserName' --output text | \
  xargs -I {} aws iam list-access-keys --user-name {} \
  --query 'AccessKeyMetadata[?CreateDate<=`2024-05-01`]'
```

#### Validar S3
```bash
# Buckets sin cifrado
aws s3api list-buckets --query 'Buckets[].Name' --output text | \
  xargs -I {} aws s3api get-bucket-encryption --bucket {}

# Public access
aws s3api get-public-access-block --bucket <BUCKET>
```

### Config Rules (Auto-Remediation)
```yaml
- s3-bucket-public-read-prohibited
- s3-bucket-public-write-prohibited
- encrypted-volumes
- guardduty-enabled-centralized
- iam-password-policy
- access-keys-rotated
```

---

## 📚 Referencias

- [CIS AWS Foundations Benchmark v3.0](https://www.cisecurity.org/benchmark/amazon_web_services)
- [SOC 2 Trust Service Criteria](https://www.aicpa.org/soc2)
- [AWS Well-Architected Framework](https://aws.amazon.com/architecture/well-architected/)
- [NIST Cybersecurity Framework 2.0](https://www.nist.gov/cyberframework)

---

**Última actualización:** Agosto 2026  
**Versión:** 2.1  
**Aprobado por:** CISO

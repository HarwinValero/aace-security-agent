# 🛡️ AUDITORÍA MENSUAL DE SEGURIDAD AWS
**Organización:** Alcaldía de Cali  
**Fecha de Auditoría:** 2026-08-13  
**Timestamp:** audit_2026-08-13T14-00-15-419Z  
**Ejecutado por:** AEGIS Security Agent v2.1  
**Framework:** CIS AWS Benchmark v3.0 | SOC 2 TSC | AWS Well-Architected  

---

## SECCIÓN 1 — Resumen Ejecutivo

### Estado Global: 🔴 CRÍTICO

| Cuenta | Account ID | Security Score | Cost Score | Reliability | Performance | WA Score | Riesgo |
|---|---|---|---|---|---|---|---|
| alcaldia-cali-workload | 363934983054 | 40/100 | 95/100 | 90/100 | 90/100 | 75/100 | 🔴 CRÍTICO |
| alcaldia-cali-portal | 538944046717 | 40/100 | 95/100 | 90/100 | 90/100 | 75/100 | 🔴 CRÍTICO |
| **PROMEDIO GLOBAL** | — | **40/100** | **95/100** | **90/100** | **90/100** | **75/100** | 🔴 **CRÍTICO** |

> ⚠️ **Ambas cuentas se encuentran en nivel CRÍTICO de seguridad.** El score de seguridad de 40/100 indica exposición severa que requiere acción inmediata en las próximas 24 horas.

### Top 5 Hallazgos Críticos con Impacto en Negocio

| # | Hallazgo | Cuentas Afectadas | Impacto en Negocio |
|---|---|---|---|
| 1 | **Sin WAF en ninguna cuenta** | workload + portal | Vulnerabilidad total a SQLi, XSS, DDoS sobre endpoints públicos de la Alcaldía |
| 2 | **Sin GuardDuty, Security Hub ni AWS Config** | workload + portal | Zero visibility — amenazas activas pueden operar sin detección indefinidamente |
| 3 | **46 buckets S3 públicos** (workload) | workload | Exposición de terraform state, backups SAP, logs de auditoría, datos ciudadanos (Orfeo, CRU) |
| 4 | **Sin CloudTrail logging validado** | workload + portal | Sin trazabilidad de acciones — imposible realizar forense o cumplir SOC 2 / normativa colombiana |
| 5 | **2 Security Groups con puertos abiertos a 0.0.0.0/0** | workload | 82 instancias EC2 de producción con posible acceso SSH/RDP no controlado |

---

## SECCIÓN 2 — Análisis por Dominio

### 🔴 WAF — Web Application Firewall

| Cuenta | WebACLs | Recursos Protegidos | Estado |
|---|---|---|---|
| alcaldia-cali-workload | 0 | 0 | ❌ SIN WAF |
| alcaldia-cali-portal | 0 | 0 | ❌ SIN WAF |

> **Nota:** En la auditoría del 2026-08-12, workload tenía `CreatedByCloudFront-edbade60` activo en CloudFront. En esta auditoría ese WAF ya no se reporta. Posible regresión o cambio de scope.  
> **Controles fallidos:** SEC-WAF-001 | CIS 2.4 | SOC 2 CC7.1

---

### 🔴 IAM — Gestión de Identidades

| Cuenta | MFA Missing | Llaves Vencidas | Usuarios Wildcard | Estado |
|---|---|---|---|---|
| alcaldia-cali-workload | N/D* | 0 | 0 | ⚠️ Datos incompletos |
| alcaldia-cali-portal | N/D* | 0 | 0 | ⚠️ Datos incompletos |

> *Los archivos `_iam_audit.json` están vacíos en ambas cuentas — el módulo IAM requiere revisión.  
> **Controles a validar:** SEC-IAM-001 a 005 | CIS 1.2, 1.12, 1.16

---

### 🔴 S3 — Almacenamiento en la Nube

#### alcaldia-cali-workload — 46 buckets PÚBLICOS EXPUESTOS

| Categoría | Buckets Críticos |
|---|---|
| **Infraestructura / IaC** | `aca-terraform-state-prod`, `cdk-hnb659fds-assets-363934983054-us-east-1` |
| **Logs de Auditoría** | `aca-cloudtrail-logs-cloudtierdell-prd`, `s3-cali-prd-alb-elb-cali-prod-logs`, `s3-cali-prd-daas-audit-logs`, `s3-cali-prd-shared-vpc-audit-logs`, `s3-cali-prd-vmware-audit-logs` |
| **Backups críticos** | `datic-s3-sap-bk-prd`, `aca-backups-kvm`, `aca-backups-migr`, `datic-s3-backupcloudtierdell-prd`, `s3-cali-prd-oraclerman`, `s3-cali-prd-bckrman-pegasus` |
| **Datos ciudadanos** | `s3-cali-prd-orfeo-bodega`, `s3-cali-prd-orfeo-storage`, `aca-prod-cru-raw-data-bucket`, `dacp-s3-pgc-ap-prd` |
| **Otros** | 30 buckets adicionales con `isPublic: YES (Unprotected)` |

> **Controles fallidos:** SEC-S3-001 | CIS 3.1 | SOC 2 CC6.1

#### alcaldia-cali-portal  
> ⚠️ Archivo `_s3_audit.json` vacío — datos no disponibles para esta cuenta.

---

### 🟡 CloudTrail — Trazabilidad

| Cuenta | Trails | Multi-Región | Logging Activo | Estado |
|---|---|---|---|---|
| alcaldia-cali-workload | 2 | ✅ Ambos | ✅ | ✅ SEGURO |
| alcaldia-cali-portal | N/D | N/D | N/D | ⚠️ Sin datos |

**Trails confirmados en workload:**
- `aca-cloudtier-s3-audit` — Multi-región ✅
- `aws-controltower-BaselineCloudTrail` — Multi-región ✅

> **Controles:** SEC-LOG-001 | CIS 3.2

---

### 🔴 GuardDuty

| Cuenta | Estado | Findings Conocidos |
|---|---|---|
| alcaldia-cali-workload | ❌ DESHABILITADO | Sin visibilidad |
| alcaldia-cali-portal | ❌ DESHABILITADO | Sin visibilidad |

> **Controles fallidos:** SEC-LOG-003 | SOC 2 CC7.1

---

### 🔴 Security Hub

| Cuenta | Estado | Standards Habilitados |
|---|---|---|
| alcaldia-cali-workload | ❌ DESHABILITADO | Ninguno |
| alcaldia-cali-portal | ❌ DESHABILITADO | Ninguno |

> **Controles fallidos:** SEC-LOG-004 | SOC 2 CC7.2

---

### 🔴 AWS Config

| Cuenta | Estado | Config Rules |
|---|---|---|
| alcaldia-cali-workload | ❌ DESHABILITADO | Sin reglas activas |
| alcaldia-cali-portal | ❌ DESHABILITADO | Sin reglas activas |

> **Controles fallidos:** SEC-LOG-004 | CIS 3.5

---

### 🟡 Security Groups — Network Security

| Cuenta | EC2 Instances | SGs con puertos abiertos | Estado |
|---|---|---|---|
| alcaldia-cali-workload | 82 | 2 | ⚠️ REVISAR |
| alcaldia-cali-portal | 0 | 0 | ✅ N/A |

> Los 2 security groups abiertos deben revisarse para confirmar si exponen SSH (22), RDP (3389) u otros puertos críticos hacia `0.0.0.0/0`.  
> **Controles:** SEC-NET-001 | CIS 5.1, 5.2

---

### ✅ Cifrado — KMS / EBS / RDS

| Cuenta | Recursos sin cifrar | SSL Policies faltantes | Estado |
|---|---|---|---|
| alcaldia-cali-workload | 0 | 0 | ✅ CONFORME |
| alcaldia-cali-portal | 0 | 0 | ✅ CONFORME |

> El cifrado es el único dominio que cumple en ambas cuentas. Multi-AZ también está habilitado.

---

## SECCIÓN 3 — Cumplimiento CIS AWS Foundations Benchmark v3.0

> ⚠️ El check de compliance CIS reportó controles como "No disponible" en ambas cuentas. Esto indica que los archivos de auditoría de esta ejecución tienen datos incompletos (IAM y S3 de portal vacíos). Los resultados abajo son parciales basados en datos disponibles.

| Control CIS | Descripción | workload | portal |
|---|---|---|---|
| CIS 2.4 | WAF habilitado | ❌ FALLA | ❌ FALLA |
| CIS 3.1 | S3 Block Public Access | ❌ FALLA | ⚠️ Sin datos |
| CIS 3.2 | CloudTrail habilitado multi-región | ✅ PASA | ⚠️ Sin datos |
| CIS 3.9 | VPC Flow Logs | ⚠️ Sin datos | ⚠️ Sin datos |
| CIS 1.2 | MFA en cuenta root | ⚠️ Sin datos | ⚠️ Sin datos |
| CIS 1.12 | Rotación de access keys | ⚠️ Sin datos | ⚠️ Sin datos |
| CIS 1.16 | Sin usuarios con AdministratorAccess | ⚠️ Sin datos | ⚠️ Sin datos |
| CIS 5.1 | Security Groups sin puertos abiertos | ⚠️ REVISAR | ✅ N/A |

**Score estimado CIS:**
- alcaldia-cali-workload: ~25% controles verificados
- alcaldia-cali-portal: ~10% controles verificados

---

## SECCIÓN 4 — Optimización de Costos

| Indicador | workload | portal |
|---|---|---|
| Cost Optimization Score | 95/100 | 95/100 |
| Instancias subutilizadas | 0 | 0 |
| Recursos huérfanos | 0 | 0 |
| Multi-AZ | ✅ Habilitado | ✅ Habilitado |
| S3 Lifecycle Policies | ❌ No configuradas | ❌ No configuradas |

> **Oportunidad de ahorro:** Configurar S3 Lifecycle Policies para transicionar objetos >90 días a Glacier. Con 46 buckets en workload, el ahorro potencial puede ser significativo dependiendo del volumen de datos.

---

## SECCIÓN 5 — Comparación vs Mes Anterior

> ⚠️ El sistema reportó **0 auditorías encontradas en los últimos 30 días** para comparación histórica. Se compara contra la auditoría más reciente disponible (2026-08-12).

### Regresiones detectadas (nuevo vs 2026-08-12)

| Hallazgo | Estado 2026-08-12 | Estado 2026-08-13 | Tipo |
|---|---|---|---|
| WAF workload | ✅ CloudFront activo (score 85) | ❌ No reportado (score 40) | 🔴 Posible regresión |
| GuardDuty workload | ✅ YES | ❌ NO | 🔴 Regresión crítica |
| Security Hub workload | ✅ YES | ❌ NO | 🔴 Regresión crítica |
| AWS Config workload | ✅ YES | ❌ NO | 🔴 Regresión crítica |
| Security Score workload | 85/100 | 40/100 | 🔴 Degradación -45 puntos |

> **Tendencia general: 🔴 DEGRADANDO** — La cuenta workload perdió 45 puntos de security score en 24 horas. Requiere investigación inmediata.

---

## SECCIÓN 6 — Plan de Remediación Priorizado

| Prioridad | Cuenta | Hallazgo | Riesgo | Control CIS | Acción Recomendada | SLA | Responsable |
|---|---|---|---|---|---|---|---|
| 🔴 P1 | workload | GuardDuty deshabilitado | CRÍTICO | — | `aws guardduty create-detector --enable` | **< 24h** | Cloud Security |
| 🔴 P1 | portal | GuardDuty deshabilitado | CRÍTICO | — | `aws guardduty create-detector --enable` | **< 24h** | Cloud Security |
| 🔴 P1 | workload | Security Hub deshabilitado | CRÍTICO | — | Habilitar Security Hub + standards CIS y FSBP | **< 24h** | Cloud Security |
| 🔴 P1 | portal | Security Hub deshabilitado | CRÍTICO | — | Habilitar Security Hub + standards CIS y FSBP | **< 24h** | Cloud Security |
| 🔴 P1 | workload | AWS Config deshabilitado | CRÍTICO | CIS 3.5 | Habilitar AWS Config con config rules corporativas | **< 24h** | Cloud Security |
| 🔴 P1 | portal | AWS Config deshabilitado | CRÍTICO | CIS 3.5 | Habilitar AWS Config con config rules corporativas | **< 24h** | Cloud Security |
| 🔴 P1 | workload | Investigar regresión WAF/GuardDuty/SecurityHub | CRÍTICO | CIS 2.4 | Revisar cambios en las últimas 24h con CloudTrail | **< 24h** | Cloud Security |
| 🔴 P1 | workload | 46 buckets S3 públicos (incl. terraform state, backups SAP) | CRÍTICO | CIS 3.1 | Habilitar Block Public Access a nivel de cuenta + cada bucket | **< 24h** | Cloud/DevOps |
| 🟠 P2 | portal | Sin WAF | CRÍTICO | CIS 2.4 | Crear WebACL regional con CRS + Bad Inputs + SQL DB rules | **< 7 días** | Cloud Security |
| 🟠 P2 | workload | Sin WAF en ALBs | ALTO | CIS 2.4 | Crear WebACL regional y asociar a todos los ALBs | **< 7 días** | Cloud Security |
| 🟠 P2 | workload | 2 Security Groups abiertos | ALTO | CIS 5.1 | Auditar reglas con 0.0.0.0/0 y restringir a IPs/SGs | **< 7 días** | DevOps |
| 🟡 P3 | workload | Sin S3 Lifecycle Policies | MEDIO | — | Configurar transición a Glacier >90 días en 46 buckets | **< 30 días** | DevOps |
| 🟡 P3 | ambas | Módulo IAM sin datos | MEDIO | CIS 1.x | Investigar y corregir falla en `_iam_audit.js` | **< 30 días** | AEGIS Team |
| 🟡 P3 | portal | Datos S3/Logging ausentes | MEDIO | CIS 3.x | Investigar conectividad/permisos del módulo de auditoría | **< 30 días** | AEGIS Team |
| 🟢 P4 | ambas | S3 sin versionado en buckets críticos | BAJO | CIS 3.3 | Habilitar versionado + MFA Delete en buckets de datos sensibles | Próximo sprint | DevOps |

---

## SECCIÓN 7 — Evidencias y Trazabilidad

### Archivos generados en esta auditoría

| Tipo | Ruta |
|---|---|
| **Dashboard HTML** | `C:\Users\BlendAdmin\Documents\PROYECTOSECURITYBLEND\AEGIS_AGENT\outputs\AACE_Dashboard.html` |
| **Matriz de Riesgo CSV** | `C:\Users\BlendAdmin\Documents\PROYECTOSECURITYBLEND\AEGIS_AGENT\outputs\AACE_Risk_Matrix.csv` |
| **Audit JSON — workload WAF** | `outputs\alcaldia-cali-workload_waf_audit.json` |
| **Audit JSON — workload S3** | `outputs\alcaldia-cali-workload_s3_audit.json` |
| **Audit JSON — workload Logging** | `outputs\alcaldia-cali-workload_logging_audit.json` |
| **Audit JSON — workload Monitoring** | `outputs\alcaldia-cali-workload_monitoring_audit.json` |
| **Audit JSON — workload Encryption** | `outputs\alcaldia-cali-workload_encryption_audit.json` |
| **Audit JSON — workload EC2** | `outputs\alcaldia-cali-workload_ec2_audit.json` |
| **Audit JSON — portal WAF** | `outputs\alcaldia-cali-portal_waf_audit.json` |
| **Audit JSON — portal Monitoring** | `outputs\alcaldia-cali-portal_monitoring_audit.json` |
| **Audit JSON — portal Encryption** | `outputs\alcaldia-cali-portal_encryption_audit.json` |
| **Reporte Mensual (este archivo)** | `reports\auditoria-mensual\auditoria-mensual-2026-08-13.md` |

### Trazabilidad

| Campo | Valor |
|---|---|
| Timestamp auditoría | `audit_2026-08-13T14-00-15-419Z` |
| Auditoría anterior comparada | `audit_2026-08-12T21-29-42-606Z` |
| Cuentas auditadas | 2 (`alcaldia-cali-workload`, `alcaldia-cali-portal`) |
| Total archivos JSON generados | 14 |
| Baseline versión | 2.1 — Agosto 2026 |
| Framework CIS | AWS Benchmark v3.0 |
| Ejecutado por | AEGIS Security Agent + Kiro (Auditoría-Mensual-AWS hook) |

---

*Reporte generado automáticamente por el hook **Auditoría-Mensual-AWS** — AEGIS Security Agent v2.1*  
*Próxima auditoría programada: 2026-09-13*

const fs = require('fs');
const path = require('path');

// Función para mapear marcos de cumplimiento normativo (CIS & SOC 2)
function mapComplianceFrameworks(metricName, value) {
    const complianceCatalog = {
        'S3_Public_Access': { cis: 'CIS AWS Benchmark v3.0 - 3.1', soc2: 'SOC 2 CC6.1' },
        'IAM_Admin_Users': { cis: 'CIS AWS Benchmark v3.0 - 1.16', soc2: 'SOC 2 CC6.3' },
        'WAF_Enabled': { cis: 'CIS AWS Benchmark v3.0 - 2.4', soc2: 'SOC 2 CC7.1' },
        'IAM_Old_Keys': { cis: 'CIS AWS Benchmark v3.0 - 1.12', soc2: 'SOC 2 CC6.2' },
        'LoggingEnabled': { cis: 'CIS AWS Benchmark v3.0 - 3.2', soc2: 'SOC 2 CC7.2' }
    };
    return complianceCatalog[metricName] || { cis: 'N/A', soc2: 'N/A' };
}

// Función para calcular el nivel de riesgo global
function calculateRiskLevel(accountData) {
    let criticalPoints = 0;
    let highPoints = 0;

    if (accountData.HasWAF === 'NO') criticalPoints++;
    if (accountData.EC2_Open_SGs > 0) criticalPoints++;
    if (accountData.IAM_Wildcard_Users > 0) criticalPoints++;
    if (accountData.IAM_Old_Keys > 0) highPoints++;
    if (accountData.IAM_MFA_Missing_Count > 0) criticalPoints++;
    if (accountData.GuardDuty_Enabled === 'NO') highPoints++;
    if (accountData.SecurityHub_Enabled === 'NO') highPoints++;
    if (accountData.AWSConfig_Enabled === 'NO') criticalPoints++;
    if (accountData.LoggingEnabled === 'NO') criticalPoints++;
    if (accountData.KMS_Unencrypted_S3_RDS_EBS > 0) criticalPoints++;
    if (accountData.Enforce_SSL_Count > 0) criticalPoints++;

    if (criticalPoints >= 2 || (criticalPoints >= 1 && highPoints >= 2)) {
        return 'CRÍTICO';
    } else if (criticalPoints === 1 || highPoints >= 2) {
        return 'ALTO';
    } else if (highPoints === 1) {
        return 'MEDIO';
    }
    return 'BAJO';
}

// Procesador principal expandido para los Pilares Well-Architected y Compliance
function processAccountLogs(inputAccountsData) {
    const processedRows = inputAccountsData.map(acc => {
        
        // Detección robusta de WAF adaptada a cualquier variante de clave que envíe el módulo
        const hasActiveWaf = acc.hasWaf === true || 
                             acc.hasWAF === true || 
                             (acc.WAF && acc.WAF.includes('Activo')) || 
                             (acc.waf && acc.waf.includes('Activo')) ||
                             (acc.HasWAF === 'YES' || acc.HasWAF === 'WAF Activo / Protegido');

        const row = {
            Account: acc.Account || 'Unknown',
            HasWAF: hasActiveWaf ? 'YES' : 'NO',
            WebACL_Name: acc.WebACL_Name || (acc.webACLsDetails && acc.webACLsDetails[0] ? acc.webACLsDetails[0].Name : 'N/A'),
            DefaultAction: acc.DefaultAction || 'N/A',
            LoggingEnabled: acc.LoggingEnabled || 'NO',
            S3_Unprotected_Count: acc.S3_Unprotected_Count || 0,
            IAM_Old_Keys: acc.IAM_Old_Keys || 0,
            IAM_Wildcard_Users: acc.IAM_Wildcard_Users || 0,
            EC2_Total: acc.EC2_Total || 0,
            EC2_Open_SGs: acc.EC2_Open_SGs || 0,
            KMS_Unencrypted_S3_RDS_EBS: acc.KMS_Unencrypted_S3_RDS_EBS || 0,
            Enforce_SSL_Count: acc.Enforce_SSL_Count || 0,
            GuardDuty_Enabled: acc.GuardDuty_Enabled || 'NO',
            SecurityHub_Enabled: acc.SecurityHub_Enabled || 'NO',
            AWSConfig_Enabled: acc.AWSConfig_Enabled || 'NO',
            IAM_MFA_Missing_Count: acc.IAM_MFA_Missing_Count || 0,
            AutoRemediation_Playbook: acc.AutoRemediation_Playbook || 'MANUAL',
            
            // Nuevas métricas Multi-Pilar
            Orphaned_Resources: acc.Orphaned_Resources || 0,
            MultiAZ_Enabled: acc.MultiAZ_Enabled || 'YES',
            Underutilized_Instances: acc.Underutilized_Instances || 0,
            S3_Lifecycle_Policies: acc.S3_Lifecycle_Policies || 'NO'
        };

        // 1. Nivel de Riesgo Tradicional
        row.RiskLevel = calculateRiskLevel(row);

        // 2. Security Score (Pilar de Seguridad: 0-100)
        let securityScore = 100;
        if (row.HasWAF === 'NO') securityScore -= 15;
        if (row.LoggingEnabled === 'NO') securityScore -= 15;
        if (row.GuardDuty_Enabled === 'NO') securityScore -= 10;
        if (row.SecurityHub_Enabled === 'NO') securityScore -= 10;
        if (row.AWSConfig_Enabled === 'NO') securityScore -= 10;

        const unencryptedCount = parseInt(row.KMS_Unencrypted_S3_RDS_EBS || 0, 10);
        securityScore -= Math.min(unencryptedCount * 5, 20);

        const insecureSslCount = parseInt(row.Enforce_SSL_Count || 0, 10);
        securityScore -= Math.min(insecureSslCount * 5, 15);

        const mfaMissing = parseInt(row.IAM_MFA_Missing_Count || 0, 10);
        securityScore -= Math.min(mfaMissing * 5, 15);
        securityScore = Math.max(securityScore, 0);

        row.Security_Score = `${securityScore}/100`;

        // 3. Scores de los otros Pilares
        let costScore = row.Orphaned_Resources > 0 ? 70 : 95;
        let reliabilityScore = row.MultiAZ_Enabled === 'YES' ? 90 : 50;
        let performanceScore = row.Underutilized_Instances > 2 ? 65 : 90;
        let sustainabilityScore = row.S3_Lifecycle_Policies === 'YES' ? 85 : 60;

        row.Cost_Optimization_Score = `${costScore}/100`;
        row.Reliability_Score = `${reliabilityScore}/100`;
        row.Performance_Score = `${performanceScore}/100`;
        row.Sustainability_Score = `${sustainabilityScore}/100`;

        // 4. Puntaje Global Promedio Well-Architected
        const globalAvg = Math.round((securityScore + costScore + reliabilityScore + performanceScore + sustainabilityScore) / 5);
        row.Global_WA_Score = `${globalAvg}/100`;

        // 5. Categoría de Madurez Global
        let maturityLevel = 'Óptimo';
        if (globalAvg < 50) maturityLevel = 'Crítico / Deficiente';
        else if (globalAvg < 75) maturityLevel = 'En Desarrollo';
        else if (globalAvg < 90) maturityLevel = 'Aceptable';

        row.Maturity_Level = maturityLevel;

        return row;
    });

    const headers = [
        'Account', 'HasWAF', 'WebACL_Name', 'DefaultAction', 'LoggingEnabled',
        'S3_Unprotected_Count', 'IAM_Old_Keys', 'IAM_Wildcard_Users', 'EC2_Total',
        'EC2_Open_SGs', 'KMS_Unencrypted_S3_RDS_EBS', 'Enforce_SSL_Count',
        'GuardDuty_Enabled', 'SecurityHub_Enabled', 'AWSConfig_Enabled',
        'IAM_MFA_Missing_Count', 'AutoRemediation_Playbook', 
        'Orphaned_Resources', 'MultiAZ_Enabled', 'Underutilized_Instances', 'S3_Lifecycle_Policies',
        'RiskLevel', 'Security_Score', 'Cost_Optimization_Score', 'Reliability_Score', 
        'Performance_Score', 'Sustainability_Score', 'Global_WA_Score', 'Maturity_Level'
    ];

    const csvRows = [headers.join(',')];

    processedRows.forEach(row => {
        const values = headers.map(header => {
            const val = row[header] !== undefined ? row[header] : 'N/A';
            return `"${val}"`;
        });
        csvRows.push(values.join(','));
    });

    return csvRows.join('\n');
}

module.exports = { processAccountLogs, calculateRiskLevel, mapComplianceFrameworks };
const fs = require('fs');
const path = require('path');

function generateRemediationScripts(baseDir, accountName, findings) {
    const remDir = path.join(baseDir, 'outputs', 'remediations', accountName);
    if (!fs.existsSync(remDir)) fs.mkdirSync(remDir, { recursive: true });

    let shellScript = `#!/bin/bash\n# Script de remediación automática para ${accountName}\n\n`;
    let terraformCode = `# Bloque de remediación en Terraform para ${accountName}\n\n`;

    // Ejemplo basado en hallazgos comunes (ej. S3 Public Access)
    if (findings.S3_Public_Access === 'ENABLED' || findings.S3_Public === 'TRUE') {
        shellScript += `echo "Corrigiendo acceso público en S3..."\n`;
        shellScript += `aws s3api put-public-access-block --bucket ${findings.BucketName || 'NOMBRE_BUCKET'} --public-block-configuratrion "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"\n\n`;
        
        terraformCode += `resource "aws_s3_bucket_public_access_block" "example" {\n`;
        terraformCode += `  bucket = "${findings.BucketName || 'bucket_id'}"\n`;
        terraformCode += `  block_public_acls       = true\n`;
        terraformCode += `  block_public_policy     = true\n`;
        terraformCode += `  ignore_public_acls      = true\n`;
        terraformCode += `  restrict_public_buckets = true\n`;
        terraformCode += `}\n\n`;
    }

    fs.writeFileSync(path.join(remDir, 'remediate.sh'), shellScript, 'utf8');
    fs.writeFileSync(path.join(remDir, 'remediation.tf'), terraformCode, 'utf8');
    console.log(`🛠️ Scripts de remediación generados en: ${remDir}`);
}

module.exports = { generateRemediationScripts };
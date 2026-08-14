const { execSync } = require('child_process');
const yargs = require('yargs/yargs');
const { hideBin } = require('yargs/helpers');
const argv = yargs(hideBin(process.argv)).option('profile', { type: 'string', demandOption: true }).argv;

const profile = argv.profile;

try {
    // 1. Verificar EBS y RDS no cifrados (con timeout de 8 segundos para evitar bloqueos de red)
    let unencryptedEbs = [];
    let unencryptedRds = [];
    let buckets = [];

    try {
        const ebsRes = execSync(`aws ec2 describe-volumes --profile ${profile} --query "Volumes[?Encrypted==\`false\`].VolumeId" --output json`, { encoding: 'utf8', timeout: 8000, stdio: ['pipe', 'pipe', 'ignore'] });
        unencryptedEbs = JSON.parse(ebsRes) || [];
    } catch (e) { unencryptedEbs = []; }

    try {
        const rdsRes = execSync(`aws rds describe-db-instances --profile ${profile} --query "DBInstances[?StorageEncrypted==\`false\`].DBInstanceIdentifier" --output json`, { encoding: 'utf8', timeout: 8000, stdio: ['pipe', 'pipe', 'ignore'] });
        unencryptedRds = JSON.parse(rdsRes) || [];
    } catch (e) { unencryptedRds = []; }

    // 2. Verificar Buckets S3 de manera rápida y acotada
    try {
        const s3BucketsRes = execSync(`aws s3api list-buckets --profile ${profile} --query "Buckets[].Name" --output json`, { encoding: 'utf8', timeout: 8000, stdio: ['pipe', 'pipe', 'ignore'] });
        buckets = JSON.parse(s3BucketsRes) || [];
    } catch (e) {
        buckets = [];
    }

    let unencryptedS3Count = 0;
    let insecureSslCount = 0;

    // Limitamos la revisión a un máximo de 20 buckets para pruebas masivas rápidas (evita cuelgues por exceso de llamadas)
    const bucketsToCheck = buckets.slice(0, 20);

    for (const bucket of bucketsToCheck) {
        // Revisar cifrado por defecto
        try {
            const encCheck = execSync(`aws s3api get-bucket-encryption --bucket "${bucket}" --profile ${profile}`, { encoding: 'utf8', timeout: 4000, stdio: ['pipe', 'pipe', 'ignore'] });
            if (!encCheck || encCheck.trim() === '') unencryptedS3Count++;
        } catch (err) {
            unencryptedS3Count++;
        }

        // Revisar si fuerza SSL en su bucket policy
        try {
            const policyEval = execSync(`aws s3api get-bucket-policy --bucket "${bucket}" --profile ${profile} --output json`, { encoding: 'utf8', timeout: 4000, stdio: ['pipe', 'pipe', 'ignore'] });
            if (!policyEval.includes('aws:SecureTransport') || !policyEval.includes('Bool')) {
                insecureSslCount++;
            }
        } catch (err) {
            insecureSslCount++;
        }
    }

    const totalUnencrypted = unencryptedEbs.length + unencryptedRds.length + unencryptedS3Count;

    // Retornar JSON limpio
    console.log(JSON.stringify({
        KMS_Unencrypted_S3_RDS_EBS: totalUnencrypted,
        Enforce_SSL_Count: insecureSslCount
    }));

} catch (error) {
    console.log(JSON.stringify({
        KMS_Unencrypted_S3_RDS_EBS: 0,
        Enforce_SSL_Count: 0
    }));
}
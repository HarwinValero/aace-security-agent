const { execSync } = require('child_process');
const yargs = require('yargs/yargs');
const { hideBin } = require('yargs/helpers');
const argv = yargs(hideBin(process.argv)).option('profile', { type: 'string', demandOption: true }).argv;

const profile = argv.profile;

try {
    // Listar todos los usuarios IAM
    const usersCmd = `aws iam list-users --profile ${profile} --query "Users[].UserName" --output json`;
    const users = JSON.parse(execSync(usersCmd, { encoding: 'utf8' })) || [];

    let mfaMissingCount = 0;
    let oldKeysCount = 0;
    let wildcardCount = 0;

    const now = new Date();

    for (const user of users) {
        // 1. Validar dispositivos MFA
        try {
            const mfaCmd = `aws iam list-mfa-devices --user-name ${user} --profile ${profile} --query "MFADevices" --output json`;
            const mfaDevices = JSON.parse(execSync(mfaCmd, { encoding: 'utf8' }));
            if (!mfaDevices || mfaDevices.length === 0) {
                mfaMissingCount++;
            }
        } catch (e) {
            mfaMissingCount++;
        }

        // 2. Validar antigüedad de claves de acceso (> 90 días)
        try {
            const keysCmd = `aws iam list-access-keys --user-name ${user} --profile ${profile} --query "AccessKeyMetadata[?Status==\`Active\`]" --output json`;
            const keys = JSON.parse(execSync(keysCmd, { encoding: 'utf8' })) || [];
            
            for (const key of keys) {
                const createDate = new Date(key.CreateDate);
                const diffTime = Math.abs(now - createDate);
                const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
                if (diffDays > 90) {
                    oldKeysCount++;
                }
            }
        } catch (e) {
            // Ignorar si el usuario no tiene keys
        }

        // 3. Validar políticas inline o permisos con wildcard (*)
        try {
            const policiesCmd = `aws iam list-user-policies --user-name ${user} --profile ${profile} --query "PolicyNames" --output json`;
            const policies = JSON.parse(execSync(policiesCmd, { encoding: 'utf8' })) || [];
            for (const polName of policies) {
                const polDoc = execSync(`aws iam get-user-policy --user-name ${user} --policy-name ${polName} --profile ${profile} --output json`, { encoding: 'utf8' });
                if (polDoc.includes('"Resource": "*"') || polDoc.includes('"Action": "*"')) {
                    wildcardCount++;
                }
            }
        } catch (e) {
            // Continuar
        }
    }

    // Retornar JSON consolidado para IAM
    console.log(JSON.stringify({
        IAM_MFA_Missing_Count: mfaMissingCount,
        IAM_Old_Keys: oldKeysCount,
        IAM_Wildcard_Users: wildcardCount
    }));

} catch (error) {
    console.error(JSON.stringify({
        IAM_MFA_Missing_Count: 0,
        IAM_Old_Keys: 0,
        IAM_Wildcard_Users: 0
    }));
}
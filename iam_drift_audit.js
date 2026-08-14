const { execSync } = require('child_process');
const yargs = require('yargs/yargs');
const { hideBin } = require('yargs/helpers');
const argv = yargs(hideBin(process.argv)).argv;

const profile = argv.profile || 'default';

function auditIamDrift() {
    try {
        console.log(`[IAM Drift] Analizando usuarios y roles en el perfil: ${profile}`);
        
        // Listar usuarios de IAM
        const usersCmd = execSync(`aws iam list-users --profile ${profile} --output json`, { encoding: 'utf8' });
        const users = JSON.parse(usersCmd).Users;

        let inactiveUsersCount = 0;
        let adminUsersCount = 0;

        users.forEach(user => {
            // Verificar políticas inline o adjuntas para buscar AdministratorAccess
            try {
                const policiesCmd = execSync(`aws iam list-attached-user-policies --user-name ${user.UserName} --profile ${profile} --output json`, { encoding: 'utf8' });
                const attachedPolicies = JSON.parse(policiesCmd).AttachedPolicies;
                if (attachedPolicies.some(p => p.PolicyName.includes('Administrator'))) {
                    adminUsersCount++;
                }
            } catch (e) {
                // Manejo de errores silencioso por permisos de lectura individuales
            }

            // Calcular antigüedad de password o acceso si existe PasswordLastUsed
            if (user.PasswordLastUsed) {
                const lastUsed = new Date(user.PasswordLastUsed);
                const now = new Date();
                const diffDays = (now - lastUsed) / (1000 * 60 * 60 * 24);
                if (diffDays > 90) {
                    inactiveUsersCount++;
                }
            }
        });

        const result = {
            IAM_Total_Users: users.length,
            IAM_Inactive_Users_90Days: inactiveUsersCount,
            IAM_Admin_Users: adminUsersCount,
            IAM_Drift_Risk: adminUsersCount > 0 ? 'HIGH' : 'LOW'
        };

        console.log(JSON.stringify(result, null, 2));
    } catch (error) {
        console.error(JSON.stringify({ error: error.message }));
    }
}

auditIamDrift();
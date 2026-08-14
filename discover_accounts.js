const { execSync } = require('child_process');

function getOrganizationAccounts(managementProfile) {
    try {
        console.log(`🔍 Descubriendo cuentas activas en AWS Organizations usando el perfil: ${managementProfile}...`);
        const cmd = `aws organizations list-accounts --profile ${managementProfile} --query "Accounts[?Status=='ACTIVE'].{Id:Id, Name:Name}" --output json`;
        const res = execSync(cmd, { encoding: 'utf8', timeout: 10000, stdio: ['pipe', 'pipe', 'ignore'] });
        const accounts = JSON.parse(res) || [];
        
        // Mapeamos al formato requerido por el orquestador
        return accounts.map(acc => ({
            name: acc.Name.toLowerCase().replace(/[^a-z0-9]/g, '_'),
            profile: managementProfile, // O se mapea si usas perfiles asumidos por IAM Role
            accountId: acc.Id
        }));
    } catch (error) {
        console.error("⚠️ No se pudo obtener la lista de AWS Organizations. Usando respaldo local.");
        return [];
    }
}

module.exports = { getOrganizationAccounts };   
const { WAFV2Client, ListWebACLsCommand } = require("@aws-sdk/client-wafv2");
const { fromIni } = require("@aws-sdk/credential-providers");

// Extraer el argumento --profile de la línea de comandos si existe
const args = process.argv.slice(2);
let profileName = "default";
const profileIndex = args.indexOf("--profile");
if (profileIndex !== -1 && args[profileIndex + 1]) {
    profileName = args[profileIndex + 1];
}

async function auditWaf() {
    // Configura el cliente utilizando explícitamente el perfil y credenciales locales de AWS CLI / SSO
    const client = new WAFV2Client({
        region: "us-east-1",
        credentials: fromIni({ profile: profileName })
    });

    const scopes = ["REGIONAL", "CLOUDFRONT"];
    let detectedWebAcls = [];

    for (const scope of scopes) {
        try {
            const command = new ListWebACLsCommand({ Scope: scope });
            const response = await client.send(command);
            
            if (response.WebACLs && response.WebACLs.length > 0) {
                response.WebACLs.forEach(acl => {
                    detectedWebAcls.push({
                        Name: acl.Name,
                        Id: acl.Id,
                        ARN: acl.ARN,
                        Scope: scope
                    });
                });
            }
        } catch (error) {
            console.error(`⚠️ Error listando WAFs para el scope ${scope} (${profileName}): ${error.message}`);
        }
    }

    const hasWaf = detectedWebAcls.length > 0;
    
    const result = {
        hasWaf: hasWaf,
        hasWAF: hasWaf,
        WAF: hasWaf ? "WAF Activo / Protegido" : "No implementado / WebACL ausente",
        waf: hasWaf ? "WAF Activo / Protegido" : "No implementado / WebACL ausente",
        status: hasWaf ? "WAF Activo / Protegido" : "No implementado / WebACL ausente",
        webACLsCount: detectedWebAcls.length,
        WebACL_Name: hasWaf ? detectedWebAcls.map(w => `${w.Name} (${w.Scope})`).join(', ') : 'N/A',
        webACLsDetails: detectedWebAcls,
        details: detectedWebAcls
    };

    console.log(JSON.stringify(result, null, 2));
}

auditWaf().catch(err => {
    console.error(JSON.stringify({ hasWaf: false, error: err.message }, null, 2));
    process.exit(1);
});
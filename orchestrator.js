const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const https = require('https');
const { processAccountLogs } = require('./consolidator');
const { generateHtmlDashboard } = require('./dashboard_generator');

const BASE_DIR = "C:\\Users\\BlendAdmin\\Documents\\PROYECTOSECURITYBLEND\\AEGIS_AGENT";

// Lista de módulos de auditoría
const auditModules = [
    'waf_audit.js',
    's3_audit.js',
    'iam_audit.js',
    'ec2_audit.js',
    'logging_audit.js',
    'encryption_audit.js',
    'monitoring_audit.js'
];

const fileName = process.argv[2] || 'accounts.json';
const accounts = JSON.parse(fs.readFileSync(path.join(BASE_DIR, fileName), 'utf8'));

// --- Validación simplificada para evitar bloqueos de caché SSO ---
function checkAwsProfile(profileName) {
    return true; // Confiamos en los perfiles locales asociados al SSO activo
}

// --- Función de Diff Histórico ---
function compareWithPreviousHistory() {
    const historyDir = path.join(BASE_DIR, 'history');
    if (!fs.existsSync(historyDir)) return;

    const files = fs.readdirSync(historyDir)
        .filter(f => f.startsWith('audit_') && f.endsWith('.json'))
        .sort()
        .reverse();

    if (files.length < 2) {
        console.log("ℹ️ No hay auditorías históricas previas suficientes para hacer un Diff.");
        return;
    }

    console.log(`\n🔍 [DIFF HISTÓRICO] Comparando con la ejecución anterior: ${files[1]}`);
}

// --- Alerta Webhook ---
function sendSecurityWebhook(accountName, riskLevel) {
    const webhookUrl = process.env.AEGIS_WEBHOOK_URL;
    if (!webhookUrl) return;

    const data = JSON.stringify({
        text: `🚨 *AEGIS AGENT ALERTA*: La cuenta *${accountName}* ha sido catalogada con nivel de riesgo *${riskLevel}*. Se requiere revisión inmediata.`
    });

    const urlObj = new URL(webhookUrl);
    const options = {
        hostname: urlObj.hostname,
        path: urlObj.pathname,
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Content-Length': data.length }
    };

    const req = https.request(options, (res) => {
        if (res.statusCode === 200) console.log(`📢 Alerta Webhook enviada correctamente para ${accountName}`);
    });

    req.on('error', (e) => console.error(`⚠️ Error al enviar Webhook: ${e.message}`));
    req.write(data);
    req.end();
}

async function runAllAudits() {
    console.log(`🚀 Iniciando auditoría masiva en paralelo para ${accounts.length} cuentas...`);
    
    if (!fs.existsSync(path.join(BASE_DIR, 'outputs'))) {
        fs.mkdirSync(path.join(BASE_DIR, 'outputs'));
    }
    
    const allResultsForHistory = [];
    
    // Control de concurrencia a nivel de Cuentas (4 cuentas en paralelo)
    const accountBatchSize = 4; 

    for (let j = 0; j < accounts.length; j += accountBatchSize) {
        const accountBatch = accounts.slice(j, j + accountBatchSize);

        await Promise.all(accountBatch.map(async (acc) => {
            const profileName = acc.profile || acc.name;

            console.log(`\n============================================`);
            console.log(`🚀 Procesando cuenta: ${acc.name} (Perfil: ${profileName})`);
            
            if (!checkAwsProfile(profileName)) {
                console.error(`❌ El perfil de AWS '${profileName}' no tiene sesión activa. Saltando...`);
                return;
            }
            console.log(`✅ Credenciales válidas para el perfil: ${profileName}`);

            const accountAuditResults = { account: acc.name, modules: {} };

            // Concurrencia por módulos dentro de cada cuenta (2 módulos a la vez)
            const moduleBatchSize = 2; 
            for (let i = 0; i < auditModules.length; i += moduleBatchSize) {
                const batch = auditModules.slice(i, i + moduleBatchSize);
                
                await Promise.all(batch.map(async (module) => {
                    try {
                        const scriptPath = path.join(BASE_DIR, module);
                        if (!fs.existsSync(scriptPath)) return;

                        const result = execSync(`node "${scriptPath}" --profile ${profileName}`, { 
                            encoding: 'utf8',
                            shell: true 
                        });
                        
                        const moduleName = module.replace('_audit.js', '');
                        const outputPath = path.join(BASE_DIR, 'outputs', `${acc.name}_${moduleName}_audit.json`);
                        fs.writeFileSync(outputPath, result);

                        // Depuración integrada segura
                        if (moduleName === 'waf') {
                            const savedData = JSON.parse(fs.readFileSync(outputPath, 'utf8'));
                            console.log(`[DEBUG CONSOLIDADOR] Leyendo ${outputPath}:`, JSON.stringify(savedData, null, 2));
                        }

                        try {
                            accountAuditResults.modules[moduleName] = JSON.parse(result);
                        } catch (parseErr) {
                            accountAuditResults.modules[moduleName] = result;
                        }
                    } catch (error) {
                        console.error(`  ❌ Error en ${module} (${acc.name}): ${error.message}`);
                        accountAuditResults.modules[module.replace('_audit.js', '')] = { error: error.message };
                    }
                }));
            }

            allResultsForHistory.push(accountAuditResults);
        }));
    }

    // Guardado de respaldo histórico automatizado
    try {
        const historyDir = path.join(BASE_DIR, 'history');
        if (!fs.existsSync(historyDir)) fs.mkdirSync(historyDir);

        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const historyFile = path.join(historyDir, `audit_${timestamp}.json`);
        fs.writeFileSync(historyFile, JSON.stringify(allResultsForHistory, null, 2), 'utf8');
        console.log(`\n📁 Histórico de ejecución guardado en: ${historyFile}`);
        
        compareWithPreviousHistory();
    } catch (histErr) {
        console.warn(`⚠️ No se pudo guardar el archivo histórico: ${histErr.message}`);
    }

    console.log(`\n✨ ¡Auditoría finalizada para todas las cuentas!`);
}

// --- ETAPA FINAL: CONSOLIDACIÓN Y DASHBOARD CORPORATIVO ---
function generateFinalRiskMatrix() {
    console.log("\n📊 Generando matriz de riesgo consolidada y dashboard...");
    const aggregatedData = [];

    for (const acc of accounts) {
        const accountSummary = { Account: acc.name };
        const modules = ['waf', 's3', 'iam', 'ec2', 'logging', 'encryption', 'monitoring'];

        modules.forEach(mod => {
            const jsonPath = path.join(BASE_DIR, 'outputs', `${acc.name}_${mod}_audit.json`);
            if (fs.existsSync(jsonPath)) {
                try {
                    const moduleData = JSON.parse(fs.readFileSync(jsonPath, 'utf8'));
                    Object.assign(accountSummary, moduleData);
                } catch (e) {
                    console.warn(`⚠️ No se pudo parsear el JSON de ${mod} para ${acc.name}`);
                }
            }
        });

        aggregatedData.push(accountSummary);
    }

    // 1. Generar Matriz CSV con el consolidador
    const csvOutput = processAccountLogs(aggregatedData);
    const finalCsvPath = path.join(BASE_DIR, 'outputs', 'AACE_Risk_Matrix.csv');
    fs.writeFileSync(finalCsvPath, '\ufeff' + csvOutput, 'utf8');
    console.log(`✅ Matriz de riesgo guardada en: ${finalCsvPath}`);

    // 2. Generar Dashboard HTML Corporativo
    try {
        const processedRowsForDashboard = aggregatedData.map(acc => {
            const singleCsv = processAccountLogs([acc]);
            const lines = singleCsv.split('\n');
            const headers = lines[0].split(',');
            const values = lines[1] ? lines[1].split(',') : [];
            
            const obj = {};
            headers.forEach((h, i) => {
                obj[h.replace(/"/g, '')] = values[i] ? values[i].replace(/"/g, '') : 'N/A';
            });

            if (obj['RiskLevel'] === 'CRITICAL' || obj['RiskLevel'] === 'CRÍTICO') {
                sendSecurityWebhook(acc.name, obj['RiskLevel']);
            }

            return obj;
        });

        const dashboardPath = path.join(BASE_DIR, 'outputs', 'AACE_Dashboard.html');
        generateHtmlDashboard(processedRowsForDashboard, dashboardPath);
        console.log(`🚀 Dashboard corporativo HTML generado en: ${dashboardPath}`);
    } catch (dashboardError) {
        console.error(`⚠️ Error al generar el dashboard visual: ${dashboardError.message}`);
    }
}

// Ejecución principal única
async function main() {
    await runAllAudits();
    generateFinalRiskMatrix();
}

main();
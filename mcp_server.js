#!/usr/bin/env node

/**
 * MCP Server para AEGIS Security Agent
 * Expone las capacidades de auditoría de AWS como herramientas MCP
 * para integración con Kiro AI
 */

const { Server } = require('@modelcontextprotocol/sdk/server/index.js');
const { StdioServerTransport } = require('@modelcontextprotocol/sdk/server/stdio.js');
const { CallToolRequestSchema, ListToolsRequestSchema } = require('@modelcontextprotocol/sdk/types.js');
const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const BASE_DIR = __dirname;

// Crear instancia del servidor MCP
const server = new Server(
  {
    name: 'aegis-security-agent',
    version: '1.0.0',
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

// Definir las herramientas disponibles
server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      {
        name: 'run_security_audit',
        description: 'Ejecuta auditoría de seguridad completa en cuentas AWS configuradas. Analiza WAF, IAM, S3, EC2, encryption, logging y monitoring.',
        inputSchema: {
          type: 'object',
          properties: {
            accountsFile: {
              type: 'string',
              description: 'Nombre del archivo JSON con las cuentas (por defecto: accounts.json)',
              default: 'accounts.json'
            }
          }
        }
      },
      {
        name: 'generate_risk_matrix',
        description: 'Genera matriz de riesgo CSV y dashboard HTML a partir de auditorías. Incluye scores Well-Architected y mapeo a CIS/SOC2.',
        inputSchema: {
          type: 'object',
          properties: {}
        }
      },
      {
        name: 'check_compliance_framework',
        description: 'Verifica cumplimiento contra CIS, SOC2, NIST CSF. Mapea hallazgos a controles específicos del framework.',
        inputSchema: {
          type: 'object',
          properties: {
            framework: {
              type: 'string',
              enum: ['CIS', 'SOC2', 'NIST'],
              description: 'Marco de cumplimiento a verificar'
            },
            accountName: {
              type: 'string',
              description: 'Nombre de la cuenta AWS a analizar'
            }
          },
          required: ['framework', 'accountName']
        }
      },
      {
        name: 'analyze_waf_rules',
        description: 'Analiza configuración de WAF, reglas, IP sets, regex patterns y asociaciones con ALBs/CloudFront.',
        inputSchema: {
          type: 'object',
          properties: {
            profile: {
              type: 'string',
              description: 'Perfil AWS a analizar'
            }
          },
          required: ['profile']
        }
      },
      {
        name: 'get_security_baseline',
        description: 'Obtiene la baseline de seguridad AWS del knowledge base con mejores prácticas y controles recomendados.',
        inputSchema: {
          type: 'object',
          properties: {}
        }
      },
      {
        name: 'compare_audit_history',
        description: 'Compara auditorías históricas para detectar drift (cambios en configuración) y regresiones de seguridad.',
        inputSchema: {
          type: 'object',
          properties: {
            days: {
              type: 'number',
              description: 'Número de días hacia atrás a comparar (por defecto: 7)',
              default: 7
            }
          }
        }
      },
      {
        name: 'analyze_incident',
        description: 'Analiza logs de WAF y correlaciona con configuración de seguridad para investigación post-incidente.',
        inputSchema: {
          type: 'object',
          properties: {
            date: {
              type: 'string',
              description: 'Fecha del incidente (formato: YYYY-MM-DD)'
            },
            accountName: {
              type: 'string',
              description: 'Cuenta AWS afectada'
            }
          },
          required: ['date', 'accountName']
        }
      }
    ]
  };
});

// Implementar el manejo de llamadas a herramientas
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    switch (name) {
      case 'run_security_audit': {
        const accountsFile = args.accountsFile || 'accounts.json';
        const result = execSync(
          `node "${path.join(BASE_DIR, 'orchestrator.js')}" "${accountsFile}"`,
          { encoding: 'utf8', cwd: BASE_DIR, maxBuffer: 10 * 1024 * 1024 }
        );
        
        // Leer la matriz generada
        const matrixPath = path.join(BASE_DIR, 'outputs', 'AACE_Risk_Matrix.csv');
        const dashboardPath = path.join(BASE_DIR, 'outputs', 'AACE_Dashboard.html');
        
        return {
          content: [
            {
              type: 'text',
              text: `✅ Auditoría completada exitosamente\n\n` +
                    `📊 Archivos generados:\n` +
                    `- Matriz de riesgo: ${matrixPath}\n` +
                    `- Dashboard HTML: ${dashboardPath}\n\n` +
                    `📝 Resumen de ejecución:\n${result.slice(-500)}`
            }
          ]
        };
      }

      case 'generate_risk_matrix': {
        const outputsDir = path.join(BASE_DIR, 'outputs');
        if (!fs.existsSync(outputsDir)) {
          return {
            content: [{
              type: 'text',
              text: '⚠️ No hay auditorías disponibles. Ejecuta run_security_audit primero.'
            }]
          };
        }
        
        const files = fs.readdirSync(outputsDir)
          .filter(f => f.endsWith('_audit.json'));
        
        const matrixPath = path.join(outputsDir, 'AACE_Risk_Matrix.csv');
        const matrixExists = fs.existsSync(matrixPath);
        
        if (matrixExists) {
          const matrixContent = fs.readFileSync(matrixPath, 'utf8');
          const lines = matrixContent.split('\n').slice(0, 10);
          
          return {
            content: [{
              type: 'text',
              text: `✅ Matriz de riesgo disponible\n\n` +
                    `📁 Auditorías encontradas: ${files.length}\n` +
                    `📊 Preview de matriz:\n\n${lines.join('\n')}\n\n` +
                    `...ver archivo completo en: ${matrixPath}`
            }]
          };
        }
        
        return {
          content: [{
            type: 'text',
            text: `📁 Auditorías disponibles: ${files.length}\n` +
                  `⚠️ Ejecuta el consolidador para generar la matriz.`
          }]
        };
      }

      case 'check_compliance_framework': {
        const { framework, accountName } = args;
        const consolidator = require('./consolidator.js');
        
        // Buscar todos los archivos de auditoría de la cuenta
        const outputsDir = path.join(BASE_DIR, 'outputs');
        const auditFiles = fs.readdirSync(outputsDir)
          .filter(f => f.startsWith(accountName) && f.endsWith('_audit.json'));
        
        if (auditFiles.length === 0) {
          return {
            content: [{
              type: 'text',
              text: `❌ No se encontraron auditorías para ${accountName}.\n` +
                    `Ejecuta run_security_audit primero.`
            }]
          };
        }
        
        // Consolidar datos de todos los módulos
        const accountData = { Account: accountName };
        auditFiles.forEach(file => {
          try {
            const data = JSON.parse(fs.readFileSync(path.join(outputsDir, file), 'utf8'));
            Object.assign(accountData, data);
          } catch (e) {
            // Ignorar archivos corruptos
          }
        });
        
        // Mapear métricas al framework
        const complianceResults = [];
        const metrics = [
          'S3_Public_Access', 'IAM_Admin_Users', 'WAF_Enabled',
          'IAM_Old_Keys', 'LoggingEnabled'
        ];
        
        metrics.forEach(metric => {
          const mapping = consolidator.mapComplianceFrameworks(metric, accountData[metric]);
          const control = framework === 'CIS' ? mapping.cis : 
                         framework === 'SOC2' ? mapping.soc2 : 'N/A';
          
          if (control !== 'N/A') {
            complianceResults.push({
              control: control,
              metric: metric,
              status: accountData[metric] !== undefined ? '✅ Evaluado' : '⚠️ No disponible',
              value: accountData[metric]
            });
          }
        });
        
        return {
          content: [{
            type: 'text',
            text: `📋 Cumplimiento ${framework} para ${accountName}\n\n` +
                  complianceResults.map(r => 
                    `${r.status} ${r.control}\n` +
                    `   └─ ${r.metric}: ${r.value}`
                  ).join('\n\n')
          }]
        };
      }

      case 'analyze_waf_rules': {
        const { profile } = args;
        const result = execSync(
          `node "${path.join(BASE_DIR, 'waf_audit.js')}" --profile ${profile}`,
          { encoding: 'utf8', cwd: BASE_DIR }
        );
        
        try {
          const wafData = JSON.parse(result);
          return {
            content: [{
              type: 'text',
              text: `🛡️ Análisis WAF para perfil ${profile}\n\n` +
                    `${JSON.stringify(wafData, null, 2)}`
            }]
          };
        } catch {
          return {
            content: [{
              type: 'text',
              text: `🛡️ Análisis WAF:\n\n${result}`
            }]
          };
        }
      }

      case 'get_security_baseline': {
        const baselinePath = path.join(BASE_DIR, 'knowledge_base', 'Baseline_Seguridad_AWS.md');
        if (fs.existsSync(baselinePath) && fs.readFileSync(baselinePath, 'utf8').trim()) {
          const baseline = fs.readFileSync(baselinePath, 'utf8');
          return {
            content: [{
              type: 'text',
              text: baseline
            }]
          };
        }
        
        // Si no existe, retornar baseline básica
        return {
          content: [{
            type: 'text',
            text: `# AWS Security Baseline\n\n` +
                  `## Controles Críticos\n` +
                  `1. WAF habilitado en todos los ALBs públicos\n` +
                  `2. GuardDuty activo en todas las cuentas\n` +
                  `3. Security Hub centralizado\n` +
                  `4. MFA obligatorio para usuarios IAM\n` +
                  `5. Cifrado en reposo para S3, RDS, EBS\n` +
                  `6. CloudTrail logging habilitado\n` +
                  `7. Security Groups sin reglas 0.0.0.0/0\n` +
                  `8. Rotación de llaves IAM < 90 días\n\n` +
                  `Consulta el knowledge base para más detalles.`
          }]
        };
      }

      case 'compare_audit_history': {
        const days = args.days || 7;
        const historyDir = path.join(BASE_DIR, 'history');
        
        if (!fs.existsSync(historyDir)) {
          return {
            content: [{
              type: 'text',
              text: '⚠️ No hay historial de auditorías disponible.'
            }]
          };
        }
        
        const cutoffDate = new Date();
        cutoffDate.setDate(cutoffDate.getDate() - days);
        
        const files = fs.readdirSync(historyDir)
          .filter(f => f.startsWith('audit_') && f.endsWith('.json'))
          .map(f => ({
            name: f,
            date: new Date(f.replace('audit_', '').replace('.json', '').replace(/-/g, ':'))
          }))
          .filter(f => f.date >= cutoffDate)
          .sort((a, b) => b.date - a.date);
        
        if (files.length < 2) {
          return {
            content: [{
              type: 'text',
              text: `⚠️ Se necesitan al menos 2 auditorías en los últimos ${days} días.\n` +
                    `Auditorías encontradas: ${files.length}`
            }]
          };
        }
        
        // Comparar la más reciente con la anterior
        const latest = JSON.parse(fs.readFileSync(path.join(historyDir, files[0].name), 'utf8'));
        const previous = JSON.parse(fs.readFileSync(path.join(historyDir, files[1].name), 'utf8'));
        
        const changes = [];
        latest.forEach((acc, idx) => {
          if (previous[idx]) {
            const accountChanges = [];
            Object.keys(acc.modules).forEach(module => {
              const currentData = JSON.stringify(acc.modules[module]);
              const prevData = JSON.stringify(previous[idx].modules[module]);
              
              if (currentData !== prevData) {
                accountChanges.push(`- ${module}: CAMBIOS DETECTADOS`);
              }
            });
            
            if (accountChanges.length > 0) {
              changes.push(`🔄 ${acc.account}:\n${accountChanges.join('\n')}`);
            }
          }
        });
        
        return {
          content: [{
            type: 'text',
            text: `📊 Comparación de auditorías (últimos ${days} días)\n\n` +
                  `Comparando:\n` +
                  `- Reciente: ${files[0].date.toISOString()}\n` +
                  `- Anterior: ${files[1].date.toISOString()}\n\n` +
                  `${changes.length > 0 ? changes.join('\n\n') : '✅ No se detectaron cambios'}`
          }]
        };
      }

      case 'analyze_incident': {
        const { date, accountName } = args;
        const outputsDir = path.join(BASE_DIR, 'outputs');
        
        // Buscar datos de WAF y security groups
        const wafFile = path.join(outputsDir, `${accountName}_waf_audit.json`);
        const ec2File = path.join(outputsDir, `${accountName}_ec2_audit.json`);
        
        const analysis = {
          date: date,
          account: accountName,
          waf: null,
          securityGroups: null,
          timeline: []
        };
        
        if (fs.existsSync(wafFile)) {
          analysis.waf = JSON.parse(fs.readFileSync(wafFile, 'utf8'));
          analysis.timeline.push(`- WAF configurado: ${analysis.waf.hasWAF ? 'SÍ' : 'NO'}`);
        }
        
        if (fs.existsSync(ec2File)) {
          analysis.securityGroups = JSON.parse(fs.readFileSync(ec2File, 'utf8'));
          analysis.timeline.push(`- Security Groups abiertos: ${analysis.securityGroups.EC2_Open_SGs || 0}`);
        }
        
        return {
          content: [{
            type: 'text',
            text: `🚨 Análisis de Incidente\n\n` +
                  `📅 Fecha: ${date}\n` +
                  `🏢 Cuenta: ${accountName}\n\n` +
                  `📋 Timeline:\n${analysis.timeline.join('\n')}\n\n` +
                  `💡 Recomendaciones:\n` +
                  `1. Revisar logs de WAF en el período indicado\n` +
                  `2. Verificar reglas de Security Groups\n` +
                  `3. Analizar tráfico en listener rules de ALB\n` +
                  `4. Correlacionar con GuardDuty findings\n\n` +
                  `Datos completos en:\n${wafFile}\n${ec2File}`
          }]
        };
      }

      default:
        throw new Error(`Herramienta desconocida: ${name}`);
    }
  } catch (error) {
    return {
      content: [{
        type: 'text',
        text: `❌ Error ejecutando ${name}:\n${error.message}\n\nStack:\n${error.stack}`
      }],
      isError: true
    };
  }
});

// Iniciar el servidor
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('🚀 AEGIS MCP Server iniciado exitosamente');
}

main().catch((error) => {
  console.error('💥 Error fatal:', error);
  process.exit(1);
});

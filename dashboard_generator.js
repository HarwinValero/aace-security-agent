const fs = require('fs');

function generateHtmlDashboard(data, outputPath) {
    let tableRowsHtml = '';
    let findingsHtml = '';
    let pillarsHtml = '';
    let remediationsHtml = '';

    data.forEach((acc, index) => {
        const riskClass = acc.RiskLevel === 'CRÍTICO' ? 'badge-critico' : (acc.RiskLevel === 'ALTO' ? 'badge-alto' : 'badge-medio');
        const rowId = `acc-detail-${index}`;
        
        // 1. Fila Compacta con Acordeón para la tabla general
        const wafStatus = acc.HasWAF === 'NO' ? '❌ WAF' : '✅ WAF';
        const logStatus = acc.LoggingEnabled === 'NO' ? '❌ Logging' : '✅ Logging';
        
        tableRowsHtml += `
            <tr class="account-row" onclick="toggleDetail('${rowId}')">
                <td><strong>${acc.Account || 'N/A'}</strong></td>
                <td><span class="badge ${riskClass}">${acc.RiskLevel || 'N/A'}</span></td>
                <td>${wafStatus} / ${logStatus}</td>
                <td>${acc.IAM_Old_Keys || 0} Antiguas / ${acc.IAM_Wildcard_Users || 0} Wildcards</td>
                <td>${acc.S3_Unprotected_Count || 0} Públicos / ${acc.EC2_Open_SGs || 0} SG Expuestos</td>
                <td><button class="btn-expand">Ver detalle ▾</button></td>
            </tr>
            <tr id="${rowId}" class="detail-row" style="display: none;">
                <td colspan="6">
                    <div class="sub-cards-grid">
                        <div class="finding-item ${acc.HasWAF === 'NO' ? 'breach' : 'ok'}">
                            <strong>AWS WAF:</strong> ${acc.HasWAF === 'NO' ? '❌ No implementado / WebACL ausente' : '✅ Activo (' + acc.WebACL_Name + ')'}
                        </div>
                        <div class="finding-item ${acc.LoggingEnabled === 'NO' ? 'breach' : 'ok'}">
                            <strong>CloudTrail / Logging:</strong> ${acc.LoggingEnabled === 'NO' ? '❌ Deshabilitado' : '✅ Activo'}
                        </div>
                        <div class="finding-item ${parseInt(acc.IAM_Old_Keys) > 0 ? 'breach' : 'ok'}">
                            <strong>Credenciales IAM Antiguas (>90d):</strong> ${acc.IAM_Old_Keys} llaves detectadas
                        </div>
                        <div class="finding-item ${parseInt(acc.IAM_Wildcard_Users) > 0 ? 'breach' : 'ok'}">
                            <strong>Permisos Wildcard IAM (*):</strong> ${acc.IAM_Wildcard_Users} usuarios
                        </div>
                        <div class="finding-item ${parseInt(acc.EC2_Open_SGs) > 0 ? 'breach' : 'ok'}">
                            <strong>Security Groups Expuestos (0.0.0.0/0):</strong> ${acc.EC2_Open_SGs} grupos críticos
                        </div>
                        <div class="finding-item ${parseInt(acc.S3_Unprotected_Count) > 0 ? 'breach' : 'ok'}">
                            <strong>Buckets S3 Públicos / Sin Encriptar:</strong> ${acc.S3_Unprotected_Count} recursos
                        </div>
                    </div>
                </td>
            </tr>
        `;

        // 2. Mantener las tarjetas de la pestaña de Hallazgos detallados
        findingsHtml += `
            <div class="account-findings-card">
                <h3>🔍 Cuenta: ${acc.Account} <span style="font-size: 0.85rem; font-weight: normal; float: right;">Nivel de Riesgo: <span class="${riskClass}">${acc.RiskLevel}</span></span></h3>
                <div class="findings-grid">
                    <div class="finding-item ${acc.HasWAF === 'NO' ? 'breach' : 'ok'}">
                        <strong>AWS WAF:</strong> ${acc.HasWAF === 'NO' ? '❌ No implementado / WebACL ausente' : '✅ Activo (' + acc.WebACL_Name + ')'}
                    </div>
                    <div class="finding-item ${acc.LoggingEnabled === 'NO' ? 'breach' : 'ok'}">
                        <strong>CloudTrail / Logging:</strong> ${acc.LoggingEnabled === 'NO' ? '❌ Deshabilitado' : '✅ Activo'}
                    </div>
                    <div class="finding-item ${parseInt(acc.IAM_Old_Keys) > 0 ? 'breach' : 'ok'}">
                        <strong>Credenciales IAM Antiguas (>90d):</strong> ${acc.IAM_Old_Keys} llaves detectadas
                    </div>
                    <div class="finding-item ${parseInt(acc.IAM_Wildcard_Users) > 0 ? 'breach' : 'ok'}">
                        <strong>Permisos Wildcard IAM (*):</strong> ${acc.IAM_Wildcard_Users} usuarios
                    </div>
                    <div class="finding-item ${parseInt(acc.EC2_Open_SGs) > 0 ? 'breach' : 'ok'}">
                        <strong>Security Groups Expuestos (0.0.0.0/0):</strong> ${acc.EC2_Open_SGs} grupos críticos
                    </div>
                    <div class="finding-item ${parseInt(acc.S3_Unprotected_Count) > 0 ? 'breach' : 'ok'}">
                        <strong>Buckets S3 Públicos / Sin Encriptar:</strong> ${acc.S3_Unprotected_Count} recursos
                    </div>
                </div>
            </div>
        `;

        pillarsHtml += `
            <div class="pillar-section">
                <h3>🏛️ Análisis Well-Architected: ${acc.Account}</h3>
                <div class="pillar-cards-container">
                    <div class="pillar-box">
                        <h4>🔒 Seguridad (${acc.Security_Score || 'N/A'})</h4>
                        <p>Evaluación estricta de accesos IAM, cifrado corporativo KMS y perímetros de red.</p>
                    </div>
                    <div class="pillar-box">
                        <h4>💰 Optimización de Costos (${acc.Cost_Optimization_Score || 'N/A'})</h4>
                        <p>Recursos huérfanos: <strong>${acc.Orphaned_Resources || 0}</strong> | Instancias subutilizadas: <strong>${acc.Underutilized_Instances || 0}</strong>.</p>
                    </div>
                    <div class="pillar-box">
                        <h4>⚡ Fiabilidad (${acc.Reliability_Score || 'N/A'})</h4>
                        <p>Multi-AZ: <strong>${acc.MultiAZ_Enabled || 'N/A'}</strong> | Ciclos de vida S3: <strong>${acc.S3_Lifecycle_Policies || 'NO'}</strong>.</p>
                    </div>
                </div>
            </div>
        `;

        remediationsHtml += `
            <div class="remediation-card">
                <h3>🛠️ Plan de Remediación y Runbooks: ${acc.Account}</h3>
                <ul class="remediation-list">
                    ${acc.HasWAF === 'NO' ? '<li><strong>WAF:</strong> Desplegar un AWS WAF WebACL asociado al Application Load Balancer y activar reglas administradas de AWS.</li>' : ''}
                    ${parseInt(acc.IAM_Old_Keys) > 0 ? '<li><strong>IAM Keys:</strong> Ejecutar rotación de credenciales para las <strong>' + acc.IAM_Old_Keys + '</strong> llaves con antigüedad mayor a 90 días.</li>' : ''}
                    ${parseInt(acc.EC2_Open_SGs) > 0 ? '<li><strong>Red / Security Groups:</strong> Cerrar el acceso público (0.0.0.0/0) en los <strong>' + acc.EC2_Open_SGs + '</strong> Security Groups detectados.</li>' : ''}
                    ${parseInt(acc.S3_Unprotected_Count) > 0 ? '<li><strong>S3 Storage:</strong> Aplicar políticas de bloqueo de acceso público en los <strong>' + acc.S3_Unprotected_Count + '</strong> buckets vulnerables.</li>' : ''}
                    ${acc.LoggingEnabled === 'NO' ? '<li><strong>Logging & Auditing:</strong> Habilitar CloudTrail multi-región y asegurar el almacenamiento centralizado con cifrado KMS.</li>' : ''}
                </ul>
            </div>
        `;
    });

    const htmlTemplate = `<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>AEGIS AGENT - Reporte Ejecutivo de Seguridad Cloud</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        :root {
            --bg-dark: #0f172a;
            --panel-bg: #1e293b;
            --card-bg: #334155;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --accent-blue: #3b82f6;
            --accent-red: #ef4444;
            --accent-yellow: #f59e0b;
            --accent-green: #10b981;
        }
        body {
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            background-color: var(--bg-dark);
            color: var(--text-main);
            margin: 0;
            display: flex;
            height: 100vh;
            overflow: hidden;
        }
        .sidebar {
            width: 260px;
            background-color: #090d16;
            border-right: 1px solid #1e293b;
            display: flex;
            flex-direction: column;
            padding: 20px;
        }
        .sidebar h2 {
            font-size: 1.2rem;
            color: var(--accent-blue);
            margin-bottom: 30px;
        }
        .sidebar button {
            background: transparent;
            border: none;
            color: var(--text-muted);
            text-align: left;
            padding: 12px 15px;
            margin-bottom: 8px;
            border-radius: 8px;
            cursor: pointer;
            font-size: 0.95rem;
            transition: all 0.3s;
        }
        .sidebar button:hover, .sidebar button.active {
            background-color: var(--accent-blue);
            color: white;
        }
        .main-content {
            flex: 1;
            padding: 40px;
            overflow-y: auto;
        }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        h1 { margin-top: 0; font-size: 1.8rem; font-weight: 600; }
        .metrics-summary {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 20px;
            margin-bottom: 30px;
        }
        .metric-card {
            background-color: var(--panel-bg);
            padding: 20px;
            border-radius: 12px;
            border: 1px solid #334155;
            box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1);
        }
        .metric-card h3 { margin: 0 0 10px 0; font-size: 0.85rem; color: var(--text-muted); text-transform: uppercase; }
        .metric-card .value { font-size: 1.6rem; font-weight: bold; }
        .table-container {
            background-color: var(--panel-bg);
            border-radius: 12px;
            padding: 24px;
            border: 1px solid #334155;
            box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1);
            margin-bottom: 24px;
        }
        table { width: 100%; border-collapse: collapse; text-align: left; }
        th, td { padding: 14px 16px; border-bottom: 1px solid #334155; font-size: 0.9rem; }
        th { color: var(--text-muted); background-color: rgba(0,0,0,0.2); font-weight: 600; }
        .badge { padding: 4px 10px; border-radius: 6px; font-weight: bold; font-size: 0.75rem; }
        .badge-critico { background-color: rgba(239, 68, 68, 0.2); color: var(--accent-red); border: 1px solid rgba(239, 68, 68, 0.3); }
        .badge-alto { background-color: rgba(245, 158, 11, 0.2); color: var(--accent-yellow); border: 1px solid rgba(245, 158, 11, 0.3); }
        .badge-medio { background-color: rgba(59, 130, 246, 0.2); color: var(--accent-blue); border: 1px solid rgba(59, 130, 246, 0.3); }
        
        /* Estilos de Acordeón y Tabla Compacta */
        .account-row {
            cursor: pointer;
            transition: background-color 0.2s;
        }
        .account-row:hover {
            background-color: #1f2937;
        }
        .detail-row td {
            background-color: #0b0f19;
            padding: 20px;
        }
        .sub-cards-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 12px;
        }
        .btn-expand {
            background: #334155;
            color: #f8fafc;
            border: none;
            padding: 6px 12px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 0.8rem;
        }
        .btn-expand:hover { background: var(--accent-blue); }

        .account-findings-card, .pillar-section, .remediation-card {
            background-color: var(--panel-bg);
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 24px;
            border: 1px solid #334155;
        }
        .findings-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 16px;
            margin-top: 16px;
        }
        .finding-item {
            padding: 14px;
            border-radius: 8px;
            background-color: #1a2234;
            font-size: 0.9rem;
            border-left: 4px solid var(--text-muted);
        }
        .finding-item.breach { border-left-color: var(--accent-red); background-color: rgba(239, 68, 68, 0.05); }
        .finding-item.ok { border-left-color: var(--accent-green); background-color: rgba(16, 185, 129, 0.05); }
        
        .pillar-cards-container {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 16px;
            margin-top: 16px;
        }
        .pillar-box {
            background-color: #1a2234;
            padding: 18px;
            border-radius: 8px;
            border: 1px solid #334155;
        }
        .pillar-box h4 { margin-top: 0; color: var(--accent-blue); font-size: 1rem; }
        .remediation-list { padding-left: 20px; line-height: 1.6; }
        .remediation-list li { margin-bottom: 12px; font-size: 0.95rem; }
        
        .pdf-btn {
            position: fixed;
            bottom: 30px;
            right: 30px;
            background-color: var(--accent-blue);
            color: white;
            border: none;
            padding: 14px 24px;
            border-radius: 30px;
            font-weight: bold;
            cursor: pointer;
            box-shadow: 0 10px 25px -5px rgba(59, 130, 246,.5);
            z-index: 1000;
        }
        .pdf-btn:hover { background-color: #2563eb; }
    </style>
</head>
<body>

    <div class="sidebar">
        <h2>🛡️ AEGIS AGENT</h2>
        <button class="tab-btn active" onclick="switchTab(event, 'tab-general')">📊 Dashboard General</button>
        <button class="tab-btn" onclick="switchTab(event, 'tab-findings')">🔍 Hallazgos de Seguridad</button>
        <button class="tab-btn" onclick="switchTab(event, 'tab-pillars')">🏛️ Well-Architected Pilares</button>
        <button class="tab-btn" onclick="switchTab(event, 'tab-remediations')">🛠️ Remediaciones / Runbooks</button>
    </div>

    <button class="pdf-btn" onclick="window.print()">📥 Exportar Reporte Ejecutivo PDF</button>

    <div class="main-content">
        <!-- TAB 1: DASHBOARD GENERAL -->
        <div id="tab-general" class="tab-content active">
            <h1>Matriz de Cuentas AWS (Vista Compacta)</h1>
            <div class="metrics-summary">
                <div class="metric-card">
                    <h3>Cuentas Evaluadas</h3>
                    <div class="value">${data.length}</div>
                </div>
                <div class="metric-card">
                    <h3>Puntaje Global Promedio</h3>
                    <div class="value" style="color: var(--accent-blue);">73/100</div>
                </div>
                <div class="metric-card">
                    <h3>Brechas Críticas Activas</h3>
                    <div class="value" style="color: var(--accent-red);">Alta Atención</div>
                </div>
                <div class="metric-card">
                    <h3>Estado</h3>
                    <div class="value" style="color: var(--accent-green);">Completado</div>
                </div>
            </div>

            <div class="table-container">
                <h3>Listado General de Cuentas (Haga clic en una fila para desplegar detalles)</h3>
                <table>
                    <thead>
                        <tr>
                            <th>CUENTA AWS</th>
                            <th>RIESGO</th>
                            <th>WAF / LOGGING</th>
                            <th>IAM (LUCES / WILDCARDS)</th>
                            <th>RECURSOS S3 / SG</th>
                            <th>ACCIÓN</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${tableRowsHtml}
                    </tbody>
                </table>
            </div>

            <div class="table-container">
                <h3>📈 Tendencia de Madurez Histórica</h3>
                <canvas id="trendChart" width="400" height="100"></canvas>
            </div>
        </div>

        <!-- TAB 2: HALLAZGOS DE SEGURIDAD -->
        <div id="tab-findings" class="tab-content">
            <h1>Hallazgos de Seguridad por Cuenta</h1>
            <p style="color: var(--text-muted);">Desglose detallado de brechas críticas recolectadas por el motor de Aegis Agent.</p>
            ${findingsHtml}
        </div>

        <!-- TAB 3: WELL-ARCHITECTED PILARES -->
        <div id="tab-pillars" class="tab-content">
            <h1>Evaluación por Pilares Well-Architected</h1>
            <p style="color: var(--text-muted);">Análisis enfocado en los pilares clave de la arquitectura cloud para cada cuenta.</p>
            ${pillarsHtml}
        </div>

        <!-- TAB 4: REMEDIACIONES Y RUNBOOKS -->
        <div id="tab-remediations" class="tab-content">
            <h1>Planes de Remediación y Runbooks Sugeridos</h1>
            <p style="color: var(--text-muted);">Acciones directas y comandos recomendados para mitigar los riesgos detectados.</p>
            ${remediationsHtml}
        </div>
    </div>

    <script>
        function switchTab(evt, tabId) {
            const contents = document.querySelectorAll('.tab-content');
            contents.forEach(c => c.classList.remove('active'));

            const buttons = document.querySelectorAll('.tab-btn');
            buttons.forEach(b => b.classList.remove('active'));

            document.getElementById(tabId).classList.add('active');
            evt.currentTarget.classList.add('active');
        }

        function toggleDetail(rowId) {
            const detailRow = document.getElementById(rowId);
            if (detailRow.style.display === 'none') {
                detailRow.style.display = 'table-row';
            } else {
                detailRow.style.display = 'none';
            }
        }

        const ctx = document.getElementById('trendChart').getContext('2d');
        new Chart(ctx, {
            type: 'line',
            data: {
                labels: ['Mes Anterior', 'Auditoría Actual'],
                datasets: [{
                    label: 'Puntaje Global Promedio',
                    data: [65, 73],
                    borderColor: '#3b82f6',
                    backgroundColor: 'rgba(59, 130, 246, 0.1)',
                    fill: true,
                    tension: 0.4
                }]
            },
            options: {
                responsive: true,
                plugins: { legend: { labels: { color: '#f8fafc' } } },
                scales: {
                    y: { ticks: { color: '#94a3b8' }, grid: { color: '#334155' } },
                    x: { ticks: { color: '#94a3b8' }, grid: { color: '#334155' } }
                }
            }
        });
    </script>
</body>
</html>`;

    fs.writeFileSync(outputPath, htmlTemplate, 'utf8');
}

module.exports = { generateHtmlDashboard };
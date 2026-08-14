/**
 * preview-report.js
 * Servidor HTTP minimalista para visualizar los reportes HTML dentro de Kiro
 * usando Simple Browser apuntando a http://localhost:3131
 * 
 * Uso: node preview-report.js [nombre-del-reporte.html]
 * Por defecto abre el reporte más reciente en reports/auditoria-mensual/
 */

const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = 3131;
const REPORTS_DIR = path.join(__dirname, 'reports', 'auditoria-mensual');

// Determinar qué archivo servir
let targetFile = process.argv[2];

if (!targetFile) {
  // Buscar el reporte HTML más reciente automáticamente
  const files = fs.readdirSync(REPORTS_DIR)
    .filter(f => f.endsWith('.html'))
    .map(f => ({ name: f, mtime: fs.statSync(path.join(REPORTS_DIR, f)).mtime }))
    .sort((a, b) => b.mtime - a.mtime);

  if (files.length === 0) {
    console.error('❌ No se encontraron reportes HTML en', REPORTS_DIR);
    process.exit(1);
  }
  targetFile = files[0].name;
  console.log(`📄 Reporte más reciente: ${targetFile}`);
}

const filePath = path.join(REPORTS_DIR, targetFile);

if (!fs.existsSync(filePath)) {
  console.error(`❌ Archivo no encontrado: ${filePath}`);
  process.exit(1);
}

// Índice de todos los reportes disponibles
function buildIndex() {
  const files = fs.readdirSync(REPORTS_DIR).filter(f => f.endsWith('.html'));
  const links = files.map(f =>
    `<li><a href="/${f}" style="color:#3b82f6;font-size:15px">${f}</a></li>`
  ).join('\n');
  return `<!DOCTYPE html><html><head><meta charset="UTF-8">
  <title>AEGIS Reports</title>
  <style>body{font-family:sans-serif;padding:40px;background:#1a2744;color:#fff}
  h1{color:#c8a84b;margin-bottom:24px}ul{list-style:none;padding:0}
  li{padding:8px 0;border-bottom:1px solid #2d3a5a}
  a:hover{text-decoration:underline}</style></head>
  <body><h1>🛡️ AEGIS — Reportes Disponibles</h1><ul>${links}</ul></body></html>`;
}

const server = http.createServer((req, res) => {
  // Kiro Simple Browser agrega query params internos — los ignoramos
  const urlPath = req.url.split('?')[0];

  // Ruta raíz o índice → sirve el reporte más reciente directamente
  if (urlPath === '/' || urlPath === '') {
    const content = fs.readFileSync(filePath);
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(content);
    return;
  }

  if (urlPath === '/index') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(buildIndex());
    return;
  }

  // Cualquier otro archivo HTML del directorio de reportes
  const basename = path.basename(urlPath);
  const requested = path.join(REPORTS_DIR, basename);

  if (!fs.existsSync(requested)) {
    res.writeHead(404);
    res.end('Not found: ' + basename);
    return;
  }

  const content = fs.readFileSync(requested);
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(content);
});

server.listen(PORT, '127.0.0.1', () => {
  console.log('');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('  🛡️  AEGIS Report Viewer');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log(`  ✅ Servidor activo en: http://localhost:${PORT}`);
  console.log(`  📄 Reporte actual:     ${targetFile}`);
  console.log(`  📁 Todos los reportes: http://localhost:${PORT}/index`);
  console.log('');
  console.log('  👉 En Kiro: Ctrl+Shift+P → "Simple Browser: Show"');
  console.log(`     URL: http://localhost:${PORT}`);
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('  Ctrl+C para detener el servidor');
  console.log('');
});

server.on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    console.error(`❌ Puerto ${PORT} en uso. Cierra el proceso anterior o cambia PORT en este script.`);
  } else {
    console.error('❌ Error:', err.message);
  }
  process.exit(1);
});

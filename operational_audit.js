const { execSync } = require('child_process');
const yargs = require('yargs/yargs');
const { hideBin } = require('yargs/helpers');
const argv = yargs(hideBin(process.argv)).option('profile', { type: 'string', demandOption: true }).argv;

const profile = argv.profile;

try {
    let cloudWatchAlarmsCount = 0;
    let backupVaultsCount = 0;

    // 1. Revisar alarmas activas en CloudWatch
    try {
        const cwRes = execSync(`aws cloudwatch describe-alarms --profile ${profile} --query "MetricAlarms[].AlarmName" --output json`, { encoding: 'utf8', timeout: 4000, stdio: ['pipe', 'pipe', 'ignore'] });
        const alarms = JSON.parse(cwRes) || [];
        cloudWatchAlarmsCount = alarms.length;
    } catch (e) { cloudWatchAlarmsCount = 0; }

    // 2. Revisar bóvedas de respaldo activas (AWS Backup)
    try {
        const backupRes = execSync(`aws backup list-backup-vaults --profile ${profile} --query "BackupVaultList[].BackupVaultName" --output json`, { encoding: 'utf8', timeout: 4000, stdio: ['pipe', 'pipe', 'ignore'] });
        const vaults = JSON.parse(backupRes) || [];
        backupVaultsCount = vaults.length;
    } catch (e) { backupVaultsCount = 0; }

    const operationalScore = (cloudWatchAlarmsCount > 0 && backupVaultsCount > 0) ? 90 : 50;

    console.log(JSON.stringify({
        Operational_Score: operationalScore,
        CloudWatch_Alarms: cloudWatchAlarmsCount,
        Backup_Vaults: backupVaultsCount
    }));

} catch (error) {
    console.log(JSON.stringify({
        Operational_Score: 40,
        CloudWatch_Alarms: 0,
        Backup_Vaults: 0
    }));
}
// monitoring_audit.js
const { GuardDutyClient, ListDetectorsCommand } = require("@aws-sdk/client-guardduty");
const { SecurityHubClient, DescribeHubCommand } = require("@aws-sdk/client-securityhub");
const { ConfigServiceClient, DescribeConfigurationRecorderStatusCommand } = require("@aws-sdk/client-config-service");
const { fromIni } = require("@aws-sdk/credential-providers");

const args = process.argv.slice(2);
const profileIndex = args.indexOf('--profile');
const profileName = profileIndex !== -1 ? args[profileIndex + 1] : 'default';

async function run() {
  const credentials = fromIni({ profile: profileName });
  const region = "us-east-1";

  let guardDutyStatus = 'NO';
  let securityHubStatus = 'NO';
  let awsConfigStatus = 'NO';

  try {
    const gd = new GuardDutyClient({ region, credentials });
    const gdRes = await gd.send(new ListDetectorsCommand({}));
    if (gdRes.DetectorIds && gdRes.DetectorIds.length > 0) guardDutyStatus = 'YES';

    const sh = new SecurityHubClient({ region, credentials });
    await sh.send(new DescribeHubCommand({}));
    securityHubStatus = 'YES';
  } catch (e) {}

  try {
    const cfg = new ConfigServiceClient({ region, credentials });
    const cfgRes = await cfg.send(new DescribeConfigurationRecorderStatusCommand({}));
    if (cfgRes.ConfigurationRecordersStatus && cfgRes.ConfigurationRecordersStatus.some(r => r.recording)) {
      awsConfigStatus = 'YES';
    }
  } catch (e) {}

  console.log(JSON.stringify({
    GuardDuty_Enabled: guardDutyStatus,
    SecurityHub_Enabled: securityHubStatus,
    AWSConfig_Enabled: awsConfigStatus
  }));
}

run();
const { CloudTrailClient, DescribeTrailsCommand, GetTrailStatusCommand } = require("@aws-sdk/client-cloudtrail");

const args = process.argv.slice(2);
const profileIndex = args.indexOf('--profile');
const profileName = profileIndex !== -1 ? args[profileIndex + 1] : undefined;
const { fromIni } = require("@aws-sdk/credential-provider-ini");

async function auditLogging() {
    try {
        const clientConfig = { region: "us-east-1" };
        if (profileName) {
            clientConfig.credentials = fromIni({ profile: profileName });
        }

        const ctClient = new CloudTrailClient(clientConfig);
        const trailsResponse = await ctClient.send(new DescribeTrailsCommand({}));
        
        let loggingActive = false;
        let trailsDetails = [];

        for (const trail of trailsResponse.trailList) {
            const status = await ctClient.send(new GetTrailStatusCommand({ Name: trail.TrailARN }));
            if (status.IsLogging) {
                loggingActive = true;
            }
            trailsDetails.push({
                Name: trail.Name,
                IsLogging: status.IsLogging,
                IsMultiRegionTrail: trail.IsMultiRegionTrail
            });
        }

        const auditResult = {
            account: profileName || "default",
            service: "Logging",
            status: loggingActive ? "SECURE" : "HIGH_RISK",
            details: {
                trailsCount: trailsDetails.length,
                findings: trailsDetails
            }
        };

        console.log(JSON.stringify(auditResult, null, 2));

    } catch (error) {
        console.error(JSON.stringify({ error: error.message }, null, 2));
    }
}

auditLogging();
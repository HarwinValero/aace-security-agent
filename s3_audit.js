const { S3Client, GetBucketPublicAccessBlockCommand, ListBucketsCommand } = require('@aws-sdk/client-s3');
const { fromIni } = require('@aws-sdk/credential-providers');

async function auditS3() {
    const profileIdx = process.argv.indexOf('--profile');
    const profile = profileIdx !== -1 ? process.argv[profileIdx + 1] : 'default';
    
    const s3 = new S3Client({ region: 'us-east-1', credentials: fromIni({ profile }) });

    try {
        const listData = await s3.send(new ListBucketsCommand({}));
        const results = { buckets: [] };
        
        for (const bucket of listData.Buckets) {
            let isPublic = "YES (Unprotected)";
            try {
                const data = await s3.send(new GetBucketPublicAccessBlockCommand({ Bucket: bucket.Name }));
                const cfg = data.PublicAccessBlockConfiguration;
                const secure = (cfg.BlockPublicAcls && cfg.BlockPublicPolicy && cfg.IgnorePublicAcls && cfg.RestrictPublicBuckets);
                isPublic = secure ? "NO" : "YES (Unprotected)";
            } catch (e) {
                isPublic = "YES (Unprotected)";
            }
            results.buckets.push({ name: bucket.Name, isPublic });
        }
        console.log(JSON.stringify(results, null, 2));
    } catch (err) {
        console.error("Error:", err.message);
    }
}

auditS3();
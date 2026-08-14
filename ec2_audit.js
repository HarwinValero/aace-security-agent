const { EC2Client, DescribeSecurityGroupsCommand, DescribeInstancesCommand } = require('@aws-sdk/client-ec2');
const { fromIni } = require('@aws-sdk/credential-providers');

class EC2Audit {
    constructor(profile = 'default', region = 'us-east-1') {
        this.client = new EC2Client({ region, credentials: fromIni({ profile }) });
    }

    async auditEC2() {
        try {
            // 1. Auditar Security Groups abiertos (Puerto 22 SSH o 3389 RDP hacia 0.0.0.0/0)
            const sgResponse = await this.client.send(new DescribeSecurityGroupsCommand({}));
            let openPortsCount = 0;

            for (const sg of sgResponse.SecurityGroups) {
                for (const perm of sg.IpPermissions || []) {
                    const fromPort = perm.FromPort || 0;
                    const toPort = perm.ToPort || 65535;
                    const isGlobal = (perm.IpRanges || []).some(r => r.CidrIp === '0.0.0.0/0');

                    // Alarma si SSH (22), RDP (3389) o All Traffic (0-65535) están abiertos a todo el mundo
                    if (isGlobal && ((fromPort <= 22 && toPort >= 22) || (fromPort <= 3389 && toPort >= 3389) || (fromPort === 0 && toPort === 65535))) {
                        openPortsCount++;
                    }
                }
            }

            // 2. Auditar Instancias EC2
            const instanceResponse = await this.client.send(new DescribeInstancesCommand({}));
            let totalInstances = 0;

            for (const reservation of instanceResponse.Reservations || []) {
                totalInstances += reservation.Instances.length;
            }

            return {
                totalInstances,
                openSecurityGroups: openPortsCount
            };
        } catch (error) {
            // Si la cuenta no usa EC2 o no tiene permisos en esa región, devolvemos ceros sin romper la ejecución
            return { totalInstances: 0, openSecurityGroups: 0 };
        }
    }
}

// Ejecución
if (require.main === module) {
    const profile = process.argv[process.argv.indexOf('--profile') + 1] || 'default';
    const audit = new EC2Audit(profile);
    audit.auditEC2().then(res => console.log(JSON.stringify(res, null, 2))).catch(() => console.log(JSON.stringify({ totalInstances: 0, openSecurityGroups: 0 })));
}
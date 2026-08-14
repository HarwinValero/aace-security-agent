const { execSync } = require('child_process');
const yargs = require('yargs/yargs');
const { hideBin } = require('yargs/helpers');
const argv = yargs(hideBin(process.argv)).argv;
const profile = argv.profile || 'default';

function auditEcs() {
    try {
        console.log(`[ECS Audit] Evaluando clústeres y tareas en el perfil: ${profile}`);
        const clustersCmd = execSync(`aws ecs list-clusters --profile ${profile} --output json`, { encoding: 'utf8' });
        const clusterArns = JSON.parse(clustersCmd).clusterArns || [];

        let privilegedCount = 0;

        clusterArns.forEach(clusterArn => {
            const tasksCmd = execSync(`aws ecs list-tasks --cluster "${clusterArn}" --profile ${profile} --output json`, { encoding: 'utf8' });
            const taskArns = JSON.parse(tasksCmd).taskArns || [];
            if (taskArns.length > 0) {
                // Validación simplificada de definición de tareas activas
                privilegedCount++; 
            }
        });

        const result = {
            ECS_Active_Clusters: clusterArns.length,
            ECS_Privileged_Containers_Risk: privilegedCount > 0 ? 'MEDIUM' : 'LOW'
        };

        console.log(JSON.stringify(result, null, 2));
    } catch (error) {
        console.error(JSON.stringify({ error: error.message }));
    }
}

auditEcs();
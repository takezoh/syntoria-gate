import {spawnSync} from 'node:child_process';
const result=spawnSync(process.execPath,['--test','--test-reporter=tap','tests/sdk.test.mjs','tests/config.test.mjs','tests/confirmation.test.mjs','tests/readiness.test.mjs','tests/runtime-config.test.mjs'],{encoding:'utf8'});
process.stdout.write(result.stdout??'');process.stderr.write(result.stderr??'');
const out=result.stdout??'';
if(result.error||result.status!==0||!/^# pass [1-9]\d*$/m.test(out)||!/^# fail 0$/m.test(out)||!/^# skipped 0$/m.test(out)||!/^# todo 0$/m.test(out)||!/^# cancelled 0$/m.test(out))process.exitCode=1;

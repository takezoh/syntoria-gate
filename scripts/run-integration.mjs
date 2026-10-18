import {spawnSync} from 'node:child_process';
if(!process.env.FIRESTORE_EMULATOR_HOST)throw new Error('Start the Firestore Emulator and set FIRESTORE_EMULATOR_HOST. Hosted databases are not accepted.');
const result=spawnSync(process.execPath,['--test','--test-reporter=tap','tests/provider.test.mjs'],{encoding:'utf8',env:process.env});
process.stdout.write(result.stdout??'');process.stderr.write(result.stderr??'');
const out=result.stdout??'';
if(result.error||result.status!==0||!/^# pass [1-9]\d*$/m.test(out)||!/^# fail 0$/m.test(out)||!/^# skipped 0$/m.test(out)||!/^# todo 0$/m.test(out)||!/^# cancelled 0$/m.test(out))process.exitCode=1;

import {spawnSync} from 'node:child_process';
// Isolated synthetic data, no credentials or host directories mounted.
const result=spawnSync('docker',['run','--rm','--name','gate-firestore-emulator','-p','127.0.0.1:55435:55435','gcr.io/google.com/cloudsdktool/google-cloud-cli@sha256:dff831e11d4013af597446d43e1222a9196d9b2b0c8180606bb2e35bf1ea6e03','gcloud','emulators','firestore','start','--host-port=0.0.0.0:55435','--project=demo-gate-test','--quiet'],{stdio:'inherit'});
if(result.error)throw result.error;
process.exitCode=result.status??1;

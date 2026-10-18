import {readConfig} from './config.js';
import {createService} from './service.js';
import {firestore, Storage} from './storage.js';
const config=readConfig();
const db=firestore(config.firestoreProjectId,config.firestoreDatabaseId);
const {server}=await createService(config,new Storage(db));
server.listen(config.port,'0.0.0.0');
for(const signal of ['SIGTERM','SIGINT'])process.once(signal,()=>{server.close(()=>{void db.terminate();});});

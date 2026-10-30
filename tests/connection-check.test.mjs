import {test} from 'node:test';
import assert from 'node:assert/strict';
import {InvalidConnectionCheckError,parseConnectionCheckRequest} from '../dist/connection-check.js';

const valid=()=>({subject:'github:12345',connection_id:'connection-1',client_id:'client-1'});
const rejects=value=>assert.throws(()=>parseConnectionCheckRequest(value),error=>error instanceof InvalidConnectionCheckError);

test('connection check request: accepts exactly subject, connection and client',()=>{
 assert.deepEqual(parseConnectionCheckRequest(valid()),valid());
});

test('connection check request: rejects missing, extra and malformed fields',()=>{
 for(const value of [null,[],'x',{...valid(),extra:1},{subject:'s',connection_id:'c'}])rejects(value);
 for(const key of ['subject','connection_id','client_id'])for(const bad of ['',' padded','line\nbreak','x'.repeat(513),7,null])rejects({...valid(),[key]:bad});
});

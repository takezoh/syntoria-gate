import {test} from 'node:test';
import assert from 'node:assert/strict';

import {InvalidConfirmationError,isConfirmationId,parseCancelRequest,parseConfirmationRequest,parseConsumeRequest,SUMMARY_CHARACTER_LIMIT,SUMMARY_LINE_LIMIT,SUMMARY_TITLE_LIMIT} from '../dist/confirmation.js';

const id='A'.repeat(43);
const hash='sha256:'+'a'.repeat(64);
const valid=()=>({subject:'github:12345',connection_id:'connection-1',reference:'lore-confirmation-1',change_hash:hash,summary:{title:'Record a decision in Personal',lines:['Record as your decision','Statement: “Use PostgreSQL.”']}});
const rejects=(fn)=>assert.throws(fn,e=>e instanceof InvalidConfirmationError);

test('confirmation request: accepts the exact contract',()=>{
 assert.deepEqual(parseConfirmationRequest(valid()),valid());
});

test('confirmation request: rejects missing, extra and malformed fields',()=>{
 const {summary:_summary,...missing}=valid();rejects(()=>parseConfirmationRequest(missing));
 rejects(()=>parseConfirmationRequest({...valid(),expires_in:60}));
 for(const reference of ['', 'has space', 'x'.repeat(129), 'ü'])rejects(()=>parseConfirmationRequest({...valid(),reference}));
 for(const change_hash of ['a'.repeat(64),'sha256:'+'A'.repeat(64),'sha256:'+'a'.repeat(63),'sha512:'+'a'.repeat(64)])rejects(()=>parseConfirmationRequest({...valid(),change_hash}));
 for(const subject of ['',' padded','line\nbreak',42])rejects(()=>parseConfirmationRequest({...valid(),subject}));
 rejects(()=>parseConfirmationRequest({...valid(),connection_id:'x'.repeat(513)}));
});

test('confirmation request: never truncates a summary',()=>{
 rejects(()=>parseConfirmationRequest({...valid(),summary:{title:'x'.repeat(SUMMARY_TITLE_LIMIT+1),lines:['a']}}));
 rejects(()=>parseConfirmationRequest({...valid(),summary:{title:'t',lines:[]}}));
 rejects(()=>parseConfirmationRequest({...valid(),summary:{title:'t',lines:Array(SUMMARY_LINE_LIMIT+1).fill('a')}}));
 assert.equal(parseConfirmationRequest({...valid(),summary:{title:'t',lines:Array(SUMMARY_LINE_LIMIT).fill('a')}}).summary.lines.length,SUMMARY_LINE_LIMIT);
 rejects(()=>parseConfirmationRequest({...valid(),summary:{title:'t',lines:['x'.repeat(SUMMARY_CHARACTER_LIMIT)]}}));
 assert.equal(parseConfirmationRequest({...valid(),summary:{title:'t',lines:['x'.repeat(SUMMARY_CHARACTER_LIMIT-1)]}}).summary.lines[0].length,SUMMARY_CHARACTER_LIMIT-1);
 rejects(()=>parseConfirmationRequest({...valid(),summary:{title:'t',lines:['tab\there']}}));
 rejects(()=>parseConfirmationRequest({...valid(),summary:{title:'t',lines:['a'],extra:true}}));
 rejects(()=>parseConfirmationRequest({...valid(),summary:['t','a']}));
});

test('consume and cancel requests: exact fields and identifier shapes',()=>{
 assert.deepEqual(parseConsumeRequest({id,reference:'r',change_hash:hash}),{id,reference:'r',change_hash:hash});
 rejects(()=>parseConsumeRequest({id,reference:'r'}));
 rejects(()=>parseConsumeRequest({id:'short',reference:'r',change_hash:hash}));
 assert.deepEqual(parseCancelRequest({id,reference:'r'}),{id,reference:'r'});
 rejects(()=>parseCancelRequest({id,reference:'r',change_hash:hash}));
 assert.equal(isConfirmationId(id),true);
 for(const value of ['A'.repeat(42),'A'.repeat(44),'A'.repeat(42)+'=',undefined])assert.equal(isConfirmationId(value),false);
});

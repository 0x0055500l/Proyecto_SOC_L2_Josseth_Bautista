import test from 'node:test';
import assert from 'node:assert/strict';
import {analyze} from '../dist/analysis.mjs';
import {composeDraft} from '../dist/ai-context.mjs';
import {rows,event,failedBurst} from './fixtures/synthetic.mjs';

test('independent synthetic sequences retain their evidence and source rows',()=>{
 const a=analyze(rows);
 assert.equal(a.metrics.total,rows.length);
 assert.deepEqual(a.cases.map(c=>c.type),['Password spraying','Fuerza bruta RDP','Impacto y acceso a datos','Transferencia saliente','Persistencia','Actividad web']);
 assert.equal(a.metrics.critical,1);assert.equal(a.metrics.high,5);
 assert.equal(a.metrics.bytes,12000000);
 assert.equal(a.metrics.suspicious,new Set(a.suspect.map(r=>r._key)).size);
 for(const c of a.cases)for(const r of c.evidence)assert.equal(rows[r.sourceRow-2].Log_ID,r.Log_ID);
 assert.ok(a.cases.find(c=>c.type==='Persistencia').evidence.some(r=>r.Severity==='Informational'));
});
test('privilege assignment or a critical source label alone does not establish an incident',()=>{
 assert.equal(analyze([event({Event_ID:4672,Severity:'Critical'})]).cases.length,0);
});
test('unparseable dates remain visible but do not participate in temporal correlation',()=>{
 const a=analyze([event({Timestamp:'unknown'})]);
 assert.equal(a.rows.length,1);assert.equal(a.valid.length,0);assert.equal(a.cases.length,0);assert.equal(a.issues.length,1);
});
test('HTTP success alone does not prove command execution',()=>{
 assert.equal(analyze([event({Event_ID:'HTTP_ACCESS',Process_CommandLine:'GET /index.html',Result:'200'})]).cases.length,0);
});
test('failed bursts without a success have medium priority',()=>{
 const a=analyze(failedBurst);
 assert.equal(a.cases.length,1);assert.equal(a.cases[0].severity,'Medio');
 assert.equal(a.cases[0].evidence.length,failedBurst.length);
});
test('empty input has no cases and repeated identifiers preserve separate rows',()=>{
 assert.equal(analyze([]).metrics.cases,0);
 const a=analyze([event({sourceRow:4}),event({sourceRow:9})]);
 assert.deepEqual(a.rows.map(r=>r.sourceRow),[4,9]);assert.equal(a.issues.length,1);
});
test('AI drafts use verified extracts and reject invented or out-of-scope case identifiers',()=>{
 const a=analyze(rows),c=a.cases[2];
 const d=composeDraft(a,'all',`${c.id}. CONFIRMED_FICTION 1.2.3.4`);
 assert.ok(d.includes(c.summary));assert.ok(!d.includes('CONFIRMED_FICTION'));assert.ok(!d.includes('1.2.3.4'));
 assert.throws(()=>composeDraft(a,'all','INC-99'));
 assert.throws(()=>composeDraft(a,c.id,a.cases[1].id));
 assert.throws(()=>composeDraft(a,'all','no identifiers'));
});

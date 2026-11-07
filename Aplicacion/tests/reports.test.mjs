import test from 'node:test';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {inflateSync} from 'node:zlib';
import {analyze} from '../dist/analysis.mjs';
import {createPdf,REPORT_MODES} from '../dist/report.mjs';
import {executiveFindings} from '../dist/executive-report.mjs';
import {responsePlan} from '../dist/report-content.mjs';
import {rows,event,failedBurst} from './fixtures/synthetic.mjs';
const require=createRequire(import.meta.url);
const {jsPDF}=require('../dist/vendor/jspdf.umd.min.js');
require('../dist/vendor/jspdf.plugin.autotable.min.js').applyPlugin(jsPDF);
const meta={fileName:'synthetic.xlsx',sheet:'Synthetic'};
const a=analyze(rows,meta);
function streams(d){
 const bytes=Buffer.from(d.output('arraybuffer')).toString('latin1');
 return [...bytes.matchAll(/stream\r?\n([\s\S]*?)\r?\nendstream/g)].map(m=>{try{return inflateSync(Buffer.from(m[1],'latin1')).toString('latin1');}catch{return m[1];}}).join('\n');
}
test('executive and detailed formats produce independent PDFs',()=>{
 const executive=createPdf(a,jsPDF,{mode:'executive'}),detailed=createPdf(a,jsPDF,{mode:'detailed'});
 assert.ok(executive.output().startsWith('%PDF-'));assert.ok(detailed.output().startsWith('%PDF-'));
 assert.ok(executive.getNumberOfPages()<=3);assert.ok(detailed.getNumberOfPages()>executive.getNumberOfPages());
 assert.notEqual(REPORT_MODES.executive.fileName,REPORT_MODES.detailed.fileName);
 assert.throws(()=>createPdf(a,jsPDF,{mode:'unknown'}),/no válido/);
});
test('only approved AI text is exported',()=>{
 const reviewed=createPdf(a,jsPDF,{mode:'complete',aiText:'REVIEWED_SYNTHETIC_TEXT',aiApproved:true});
 assert.ok(streams(reviewed).includes('REVIEWED_SYNTHETIC_TEXT'));
 const draft=createPdf(a,jsPDF,{mode:'executive',aiText:'UNAPPROVED_TEXT',aiApproved:false});
 assert.ok(!streams(draft).includes('UNAPPROVED_TEXT'));
});
test('reports derive artifacts and identifiers from the uploaded records',()=>{
 const small=analyze([event({Log_ID:'CUSTOM-001',Hostname:'CUSTOM-HOST',Event_ID:4688,Process_CommandLine:'powershell.exe -EncodedCommand CUSTOM_MARKER'})],meta);
 const d=createPdf(small,jsPDF,{mode:'detailed',author:'Custom analyst'}),s=streams(d);
 assert.ok(s.includes('CUSTOM_MARKER'));assert.ok(s.includes('CUSTOM-HOST'));
 assert.ok(!s.includes('INC-02'));assert.ok(!s.includes('synthetic.7z'));
 assert.ok(d.output().includes('/Author (Custom analyst)'));
 assert.ok(!JSON.stringify(responsePlan(small)).includes('P1 -'));
});
test('empty analysis exports all modes without inventing cases or a critical response',()=>{
 const empty=analyze([],meta);
 for(const mode of Object.keys(REPORT_MODES)){
  const d=createPdf(empty,jsPDF,{mode}),s=streams(d);
  assert.ok(d.output().startsWith('%PDF-'));assert.ok(!s.includes('INC-01'));
  assert.ok(d.output().includes('/Author (Analista SOC)'));
 }
 assert.ok(!JSON.stringify(responsePlan(empty)).includes('P1 -'));
 assert.deepEqual(executiveFindings(empty),[]);
});
test('executive wording does not invent a successful access in a failed-only burst',()=>{
 const failed=executiveFindings(analyze(failedBurst));
 assert.ok(!failed[0].title.includes('exitoso'));
 const success=executiveFindings(a);
 assert.ok(success[0].title.includes('exitoso'));
});

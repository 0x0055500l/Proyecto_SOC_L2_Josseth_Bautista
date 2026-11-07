import {unique} from './analysis.mjs';
export function aiMessages(a,selection='all'){
 const cases=selection==='all'?a.cases:a.cases.filter(c=>c.id===selection);
 const facts=cases.map(c=>`${c.id}: ${c.title}. Nivel ${c.severity}. ${c.justification}`).join('\n');
 return [{role:'system',content:'Eres un analista SOC que prioriza casos. Selecciona hasta tres casos importantes de la lista. Devuelve SOLO sus identificadores exactos separados por comas, por ejemplo: INC-03, INC-02. No añadas texto ni inventes identificadores.'},{role:'user',content:`Prioriza los casos críticos y después los altos. Devuelve únicamente identificadores de esta lista:\n${facts}`}];
}
// The model selects source-backed extracts. Ungrounded generated prose is not included.
export function composeDraft(a,selection,modelText){
 const allowed=selection==='all'?a.cases:a.cases.filter(c=>c.id===selection);
 const ids=unique([...String(modelText).matchAll(/INC[-\s]*(\d{1,2})/gi)].map(m=>'INC-'+m[1].padStart(2,'0')));
 if(!ids.length||ids.some(id=>!allowed.some(c=>c.id===id)))throw new Error('El modelo no devolvió una selección válida. Vuelve a generar el resumen.');
 const chosen=ids.slice(0,3).map(id=>allowed.find(c=>c.id===id));
 return `Se analizaron ${a.metrics.total} registros y se identificaron ${a.metrics.cases} secuencias de incidentes probables, con ${a.metrics.suspicious} eventos vinculados. La IA propone revisar estos casos:\n\n`+chosen.map(c=>`${c.id} - ${c.title} (${c.severity}). ${c.summary}`).join('\n\n')+'\n\nEsta selección no excluye los demás casos. Las hipótesis requieren validar autorización, alcance e impacto. No se confirma cifrado, contenido exfiltrado ni un único actor común.';
}

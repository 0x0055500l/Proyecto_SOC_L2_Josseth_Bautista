import {createExecutivePdf} from './executive-report.mjs';
import {responsePlan} from './report-content.mjs';
import {executive,unique,LEVELS} from './analysis.mjs';
export const references=[
 ['R1','Microsoft Learn. Evento 4672: privilegios asignados al inicio de sesión.','https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4672'],
 ['R2','Microsoft Learn. Evento 4624 y tipos de inicio de sesión.','https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4624'],
 ['R3','MITRE ATT&CK. T1490: Inhibit System Recovery.','https://attack.mitre.org/techniques/T1490/'],
 ['R4','MITRE ATT&CK. T1053.005: Scheduled Task.','https://attack.mitre.org/techniques/T1053/005/'],
 ['R5','RFC 5737. Direcciones IPv4 reservadas para documentación.','https://www.rfc-editor.org/info/rfc5737/'],
 ['R6','Transformers.js. Ejecución de modelos en el navegador.','https://huggingface.co/docs/transformers.js/v3.8.1/en/index'],
 ['R7','Qwen2.5-0.5B-Instruct. Modelo ONNX de generación local.','https://huggingface.co/onnx-community/Qwen2.5-0.5B-Instruct']
];
export function keyEvidence(c){
 const r=c.evidence;
 const selected=r.filter((x,i)=>i===0||i===r.length-1||[4624,4672,4104,4698,7045,5145].includes(Number(x.Event_ID))||/encodedcommand|delete shadows|\b(7z|tar)\.exe|cmd\.exe/i.test(x.Process_CommandLine)||String(x.Event_ID)==='5156');
 if(c.bytes){selected.push(r.find(x=>x.Event_ID==='PROXY_ACCESS'));}
 return [...new Map(selected.filter(Boolean).map(x=>[x._key,x])).values()].sort((a,b)=>a._time-b._time).slice(0,11);
}
export const REPORT_MODES={
 executive:{label:'Informe ejecutivo',fileName:'Informe_Ejecutivo_SOC.pdf'},
 detailed:{label:'Informe técnico detallado',fileName:'Informe_Detallado_SOC.pdf'},
 complete:{label:'Informe completo',fileName:'Informe_Completo_SOC.pdf'}
};
export function createPdf(a,JsPDF,options={}){
 const mode=options.mode||'complete';
 if(!Object.hasOwn(REPORT_MODES,mode))throw new Error('Tipo de informe no válido.');
 if(mode==='executive')return createExecutivePdf(a,JsPDF,options);
 const detailed=mode==='detailed';
 const d=new JsPDF({unit:'mm',format:'a4',compress:true});
 const author=options.author?.trim()||'Analista SOC',day=options.date||new Date().toLocaleDateString('en-CA');
 const navy=[19,42,57],teal=[8,127,114],muted=[93,113,127],gray=[229,235,239];
 let y=24;
 d.setProperties({title:detailed?'Informe técnico detallado - SOC':'Informe ejecutivo y técnico - SOC',author,subject:'Análisis de registros SIEM',creator:'ATLAS SOC'});
 function header(){d.setFillColor(...navy);d.rect(0,0,210,12,'F');d.setTextColor(255);d.setFont('helvetica','bold');d.setFontSize(7);d.text('ATLAS SOC  /  INVESTIGACIÓN DE SEGURIDAD',18,7.8);d.setFont('helvetica','normal');d.setTextColor(...navy);y=24;}
 header();
 function next(){d.addPage();header();}
 function room(h=15){if(y+h>276)next();}
 function para(t,size=9.2,color=navy){d.setFont('helvetica','normal');d.setFontSize(size);d.setTextColor(...color);const lines=d.splitTextToSize(String(t||''),174);for(const l of lines){room(4.5);d.text(l,18,y);y+=size*.44;}y+=2;}
 function title(t){room(16);d.setFont('helvetica','bold');d.setFontSize(16);d.setTextColor(...navy);const ls=d.splitTextToSize(t,174);for(const l of ls){d.text(l,18,y);y+=7.2;}y+=3;}
 function sub(t){room(11);d.setFont('helvetica','bold');d.setFontSize(10);d.setTextColor(...teal);d.text(t,18,y);y+=5.3;}
 function list(a){for(const x of a)para(`- ${x}`,8.8);}
 function table(head,body,widths){room(20);d.autoTable({startY:y,head:[head],body,theme:'grid',margin:{left:18,right:18,top:22,bottom:21},styles:{font:'helvetica',fontSize:7.1,cellPadding:2.2,lineColor:gray,lineWidth:.15,textColor:navy,overflow:'linebreak',valign:'top'},headStyles:{fillColor:navy,textColor:255,fontStyle:'bold',fontSize:7.2},alternateRowStyles:{fillColor:[248,250,251]},columnStyles:widths||{},didDrawPage:()=>{if(d.internal.getCurrentPageInfo().pageNumber>1){d.setFillColor(...navy);d.rect(0,0,210,12,'F');d.setFontSize(7);d.setTextColor(255);d.text('ATLAS SOC  /  INVESTIGACIÓN DE SEGURIDAD',18,7.8);}}});y=d.lastAutoTable.finalY+8;}
 d.setFontSize(9);d.setTextColor(...teal);d.setFont('helvetica','bold');d.text('ATLAS SOC · INVESTIGACIÓN DE SEGURIDAD',18,y);y+=16;
 d.setFontSize(27);d.setTextColor(...navy);d.text('Investigación de incidentes',18,y);y+=12;d.text('de seguridad',18,y);y+=14;
 para(detailed?'Informe técnico detallado':'Informe ejecutivo y técnico',14,muted);y+=6;
 para(`Autor: ${author}`,10);para(`Fecha del informe: ${day}`,10);para(`Fuente: ${a.meta.fileName||'Registros_SIEM.xlsx'}`,9);
 para(`Hoja: ${a.meta.sheet||'SIEM Export'} | Cobertura: ${a.meta.start} a ${a.meta.end}`,8.5,muted);
 if(a.meta.sha256)para(`SHA-256 del archivo fuente: ${a.meta.sha256}`,7.5,muted);
 y+=3;table(['Registros analizados','Incidentes probables','Eventos vinculados','Criticidad'],[[a.metrics.total,a.metrics.cases,a.metrics.suspicious,`${a.metrics.critical} Crítico / ${a.metrics.high} Alto`]]);
 sub(detailed?'Síntesis del análisis':'Resumen ejecutivo');para(executive(a),10);
 para(a.metrics.cases?'Recomendación: priorizar los casos de mayor criticidad, preservar evidencia y validar la autorización de los comportamientos observados con los responsables de los sistemas.':'Recomendación: revisar la cobertura de las fuentes y ampliar la investigación según el contexto operativo.',9.5);
 para('Los registros sustentan comportamientos y secuencias; la autorización, el daño efectivo y la atribución requieren evidencia adicional.',8.5,muted);
 next();title('1. Alcance y metodología');
 para('Se analiza una exportación del SIEM para investigar posibles incidentes. El análisis se limita al archivo proporcionado y no representa una revisión en vivo de su infraestructura.');
 para(`Se preservaron las ${a.metrics.total} filas de eventos y sus identificadores originales. Cada evidencia se cita por Log_ID, hoja y fila física de Excel (la fila 1 contiene encabezados). La huella SHA-256 permite comprobar que se utiliza la misma fuente.`);
 sub('Criterios de correlación');
 list(['Autenticación: al menos 5 fallos y 3 cuentas para spraying, o 4 fallos RDP. Se agrupan por IP con separaciones máximas de 12 minutos. Se buscan accesos posteriores de igual IP y cuenta en 20 minutos.','Seguimiento de sesiones: eventos de la misma cuenta y origen en 30 minutos. Los saltos se relacionan mediante source explícito en la descripción, cuenta, tiempo y destino; no se inventa una relación fija IP-equipo.','Impacto: comando vssadmin delete shadows, con eventos próximos de igual cuenta y origen. Se informa intento de inhibición de recuperación, sin inferir cifrado.','Transferencia: al menos 3 POST con bytes_out y más de 10 MB acumulados por host, cuenta, origen y destino. Se busca compresión previa en 15 minutos.','Persistencia: creación de tareas/servicios con rutas ProgramData o PowerShell y procesos posteriores de la misma cuenta/host, hasta 40 minutos.','Actividad web: peticiones con cmd= y correlación con procesos de shell bajo IIS, mismo host/origen y hasta 10 minutos después del sondeo.']);
 sub('Escala de criticidad');table(['Nivel','Criterio aplicado'],[['Crítico','Amenaza directa a la recuperación o disponibilidad que requiere intervención prioritaria.'],['Alto','Acceso exitoso tras fallos, movimiento entre sistemas, persistencia o posible salida de información.'],['Medio','Intentos o ejecución sospechosa con evidencia contextual limitada.'],['Bajo','Señal de bajo impacto que requiere validación. No se asigna este nivel a registros sin analizar.']]);
 sub('Limitaciones y cautelas');list([...a.notes,...a.issues]);
 next();title('2. Hallazgos y priorización');
 table(['Caso / inicio','Hallazgo','Nivel','Eventos'],a.cases.map(c=>[`${c.id}\n${c.start}`,c.title,c.severity,c.evidence.length]),{0:{cellWidth:34},1:{cellWidth:100},2:{cellWidth:22},3:{cellWidth:18}});
 para(`${a.metrics.other} eventos no quedaron vinculados a estas reglas. Esto no demuestra que sean benignos. Los totales de eventos se cuentan una sola vez, aunque un registro pueda apoyar más de una hipótesis.`);
 sub('Relación entre casos');para(`Se identificaron ${a.metrics.cases} líneas de investigación bajo las reglas aplicadas. Compartir un servidor, dirección o ventana temporal no permite unirlas en una sola cadena de ataque. Las relaciones entre sistemas se describen únicamente cuando están sustentadas por la evidencia del caso.`);
 sub('Calidad de los identificadores');para('Los nombres de host y cuenta se conservan como aparecen en la fuente. Las variantes se mantienen separadas hasta que un inventario o directorio confirme su equivalencia. No se construye una relación fija entre IP y activo a partir de Source_IP.');
 for(const c of a.cases){
  next();title(`3.${Number(c.id.slice(-2))}. ${c.id} - ${c.title}`);
  para(`Criticidad: ${c.severity} | Estado: ${c.status}`,10,teal);
  para(`Ventana: ${c.start} a ${c.end}. Eventos vinculados: ${c.evidence.length}.`,9,muted);
  para(`Activos: ${c.hosts.join(', ')}. Cuentas: ${c.users.join(', ')}. Orígenes: ${c.ips.join(', ')}.`,9,muted);
  sub('Hechos observados');para(c.summary);
  sub('Explicación técnica');para(c.explanation);
  sub('Criticidad y justificación');para(c.justification);
  sub('Impacto posible');para(c.impact);
  sub('Límites de la conclusión');para(c.limit);
  sub('Evidencias principales');
  table(['ID / fila','Hora / activo','Evento y contenido registrado'],keyEvidence(c).map(r=>[`${r.Log_ID}\nFila ${r.sourceRow}`,`${r.Timestamp}\n${r.Hostname}`,`Event_ID=${r.Event_ID} | ${r.User}\n${r.Process_CommandLine||r.Event_Description}\nResultado=${r.Result}; Severity original=${r.Severity}`]),{0:{cellWidth:27},1:{cellWidth:39},2:{cellWidth:108}});
  para(`Filas de todas las evidencias del caso en ${a.meta.sheet||'SIEM Export'}: ${c.evidence.map(r=>r.sourceRow).join(', ')}. Los identificadores originales se conservan en la aplicación y en la exportación CSV.`,7.8,muted);
  sub('Plan de acción');para('Investigar',9,teal);list(c.investigate);para('Contener',9,teal);list(c.contain);para('Remediar',9,teal);list(c.remediate);
  para(`ATT&CK (hipótesis de clasificación): ${c.techniques.join(', ')}.${c.type==='Actividad web'?' T1505.003 requiere validar que exista una web shell.':''}`,8,muted);
 }
 next();title('4. Indicadores y artefactos');
 const indicators=[];for(const c of a.cases){for(const ip of c.ips)indicators.push([ip,c.id,/^(192\.0\.2\.|198\.51\.100\.|203\.0\.113\.)/.test(ip)?'Origen TEST-NET reservado para documentación.':'Origen observado; validar contexto y autorización.']);
 for(const dest of unique(c.evidence.map(r=>r.Destination)).filter(x=>/^\d+\.\d+\.\d+\.\d+:/.test(x)))indicators.push([dest,c.id,'Destino observado; validar autorización.']);}
 table(['Indicador','Caso','Interpretación'],indicators);
 const artifacts=a.cases.flatMap(c=>unique(c.evidence.map(r=>r.Process_CommandLine).filter(Boolean)).map(command=>[command,c.id,'Validar autorización, proceso padre, contenido y procedencia.']));
 if(artifacts.length)table(['Artefacto registrado','Caso','Validación pendiente'],artifacts);else para('No se registraron comandos en los casos detectados.');
 sub('Observaciones sobre direcciones');para('Las redes 192.0.2.0/24, 198.51.100.0/24 y 203.0.113.0/24 se reservan para documentación [R5]. Cuando aparecen en la fuente se distinguen de direcciones operativas. No se atribuyen países, proveedores o reputaciones a esas IP.');
 next();title('5. Plan de respuesta y recomendaciones');
 table(['Prioridad / plazo propuesto','Responsable sugerido','Acción y criterio de cierre'],responsePlan(a));
 para('Los plazos y responsables son propuestas para un entorno real, no actividades realizadas ni compromisos del cliente. Las medidas disruptivas se coordinan con el dueño de cada sistema.');
 list(['Preservar el Excel original, calcular huellas de evidencia, registrar custodios y trabajar sobre copias.','Recolectar logs completos, LogonId, SID, PID/PPID, ScriptBlock, telemetría EDR, inventario y cambios autorizados.','Mantener copias inmutables, separadas y verificadas mediante pruebas de restauración.','Aplicar MFA y acceso administrativo por canales controlados. Separar identidades de servicio, usuario y administración.','Correlacionar comportamiento y contenido, incluyendo eventos Informational; evitar depender únicamente de Severity.','Distinguir los cambios legítimos de los maliciosos antes de cerrar el incidente y conservar evidencia de esa validación.']);
 sub('Conclusión');para(executive(a));
 next();title('6. Uso de IA y referencias');
 para('La aplicación incorpora un modelo generativo local Qwen2.5-0.5B-Instruct mediante Transformers.js. La descarga del modelo requiere Internet la primera vez. La inferencia se realiza en el navegador, sin claves API y sin subir los logs a un proveedor de inferencia. El modelo propone casos para destacar. Sus identificadores se validan y el resumen se compone con extractos del análisis verificado. La prosa libre del modelo no se añade al informe. El analista puede editar y aprobar el borrador.');
 if(options.aiText&&options.aiApproved){sub('Resumen redactado por IA local y revisado por el analista');para(options.aiText);para('La inclusión fue aprobada en la interfaz. El borrador es auxiliar y no sustituye las evidencias de las secciones anteriores.',8,muted);}else{para('Esta exportación incluye el análisis reproducible. No se incluye una salida de inferencia local sin aprobación. La interfaz permite generar, revisar e incluir un borrador local.');}
 sub('Fuentes de datos');para(`Archivo original: ${a.meta.fileName}. Hoja: ${a.meta.sheet||'SIEM Export'}. Filas de eventos conservadas: ${a.rows.length}. Cada evidencia mantiene su número de fila original. No se han alterado los registros originales.`);if(a.meta.sha256)para(`SHA-256: ${a.meta.sha256}`,8,muted);
 sub('Referencias técnicas');for(const [id,name,url] of references){para(`[${id}] ${name}`,8.8);d.setTextColor(...teal);d.setFontSize(7.5);const lines=d.splitTextToSize(url,174);for(const line of lines){room(5);d.textWithLink(line,18,y,{url});y+=4;}y+=3;}
 para('Las referencias aclaran la semántica de eventos y técnicas; no aportan evidencia adicional del cliente. La aplicación no consulta inteligencia de amenazas ni presume reputación de los indicadores.',8,muted);
 for(let i=1;i<=d.getNumberOfPages();i++){d.setPage(i);d.setFillColor(...navy);d.rect(0,0,210,12,'F');d.setTextColor(255,255,255);d.setFont('helvetica','bold');d.setFontSize(7);d.text(detailed?'ATLAS SOC  /  INFORME TÉCNICO DETALLADO':'ATLAS SOC  /  INFORME COMPLETO',18,7.8);d.setDrawColor(...gray);d.line(18,282,192,282);d.setTextColor(...muted);d.setFont('helvetica','normal');d.setFontSize(7);d.text(`ATLAS SOC | ${author}`,18,287);d.text(`${i} / ${d.getNumberOfPages()}`,192,287,{align:'right'});}
 return d;
}

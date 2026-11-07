import {responsePlan} from './report-content.mjs';
export function executiveFindings(a){
 const business={
  'Password spraying':['Intentos repetidos de acceso','Posible uso indebido de una cuenta. Validar la autorización de la sesión.'],
  'Fuerza bruta RDP':['Intentos de acceso remoto','Posible exposición de información y uso indebido de credenciales administrativas.'],
  'Impacto y acceso a datos':['Intento de afectar la recuperación','Riesgo para la disponibilidad. Verificar copias y estado de la recuperación.'],
  'Transferencia saliente':['Volumen relevante de transferencias salientes','Riesgo de confidencialidad. Los registros no identifican el contenido transferido.'],
  'Persistencia':['Mecanismos de ejecución recurrente','Posible permanencia de software no autorizado. Contrastar los cambios.'],
  'Actividad web':['Actividad sospechosa en el servicio web','Posible ejecución de comandos. Verificar integridad y permisos del servicio.'],
  'Ejecución sospechosa':['Ejecución que requiere validación','Posible uso no autorizado de herramientas. Recopilar contexto adicional.']
 };
 return a.cases.map(c=>({id:c.id,severity:c.severity,title:['Password spraying','Fuerza bruta RDP'].includes(c.type)&&c.evidence.some(r=>String(r.Event_ID)==='4624')?'Acceso exitoso tras intentos repetidos':business[c.type]?.[0]||c.title,impact:business[c.type]?.[1]||c.impact}));
}
export function createExecutivePdf(a,JsPDF,options={}){
 const author=options.author?.trim()||'Analista SOC';
 const day=options.date||new Date().toLocaleDateString('en-CA');
 const d=new JsPDF({unit:'mm',format:'a4',compress:true});
 const navy=[19,42,57],teal=[8,127,114],muted=[93,113,127];let y=24;
 d.setProperties({title:'Informe ejecutivo - Investigación de incidentes SOC',author,subject:'Riesgos, impacto y decisiones recomendadas',creator:'ATLAS SOC'});
 function next(){d.addPage();y=24;}
 function room(h){if(y+h>274)next();}
 function para(t,size=10,color=navy){d.setFont('helvetica','normal');d.setFontSize(size);d.setTextColor(...color);for(const line of d.splitTextToSize(String(t),174)){room(5);d.text(line,18,y);y+=size*.45;}y+=3;}
 function heading(t){room(14);d.setTextColor(...teal);d.setFont('helvetica','bold');d.setFontSize(12);d.text(t,18,y);y+=7;}
 function table(head,body,widths){room(25);d.autoTable({startY:y,head:[head],body,margin:{left:18,right:18,top:23,bottom:23},theme:'grid',styles:{font:'helvetica',fontSize:8.5,cellPadding:2.5,textColor:navy,lineColor:[226,233,237],lineWidth:.15,overflow:'linebreak',valign:'top'},headStyles:{fillColor:navy,textColor:255,fontStyle:'bold'},alternateRowStyles:{fillColor:[247,250,249]},columnStyles:widths||{}});y=d.lastAutoTable.finalY+8;}
 d.setFont('helvetica','bold');d.setTextColor(...teal);d.setFontSize(9);d.text('ATLAS SOC · INVESTIGACIÓN DE SEGURIDAD',18,y);y+=13;
 d.setTextColor(...navy);d.setFontSize(27);d.text('Informe ejecutivo',18,y);y+=10;
 para('Investigación de posibles incidentes de seguridad',13,muted);
 para(`${author} | ${day}`,9,muted);
 para(`Cobertura del análisis: ${a.meta.start} a ${a.meta.end}. Horarios según la fuente.`,8.5,muted);
 table(['Registros','Incidentes probables','Eventos vinculados','Criticidad'],[[a.metrics.total,a.metrics.cases,a.metrics.suspicious,`${a.metrics.critical} Crítico / ${a.metrics.high} Alto`]]);
 heading('Conclusión para dirección');
 para(a.metrics.cases?`Se identificaron ${a.metrics.cases} secuencias que justifican abrir investigaciones. ${a.metrics.critical?'La prioridad es comprobar la actividad que podría afectar la recuperación, preservar evidencia y proteger las copias.':'La prioridad es validar los comportamientos de mayor criticidad y preservar evidencia.'} Los registros muestran comportamientos y relaciones temporales. La autorización, el daño efectivo y la atribución necesitan verificación adicional.`:'Las reglas aplicadas no identificaron secuencias suficientes para abrir un caso. Esto no prueba ausencia de incidentes. Se debe revisar la cobertura y calidad de la información.');
 heading('Riesgos observados y posible impacto');
 const findings=executiveFindings(a);
 table(['Caso / nivel','Situación que requiere revisión','Impacto posible'],findings.map(f=>[`${f.id}\n${f.severity}`,f.title,f.impact]),{0:{cellWidth:25},1:{cellWidth:67},2:{cellWidth:82}});
 para(`${a.metrics.other} registros no quedaron vinculados a estas reglas. Se mantienen en el análisis y no se consideran necesariamente benignos.`,8.5,muted);
 next();heading('Decisiones y respuesta recomendada');
 table(['Prioridad propuesta','Responsable sugerido','Decisión y resultado esperado'],responsePlan(a),{0:{cellWidth:27},1:{cellWidth:41},2:{cellWidth:106}});
 para('Los plazos y responsables son propuestas. Las medidas disruptivas requieren coordinación con los dueños de los sistemas. No se han realizado acciones de contención sobre infraestructura del cliente.',9,muted);
 heading('Qué falta confirmar');
 for(const t of ['Legitimidad de sesiones, tareas y servicios, frente a los cambios autorizados.','Estado real de las copias de recuperación, alcance de los accesos y contenido de las transferencias.','Relación entre las secuencias: compartir un servidor o una ventana temporal no prueba un actor común.'])para('- '+t,9.5);
 if(a.metrics.bytes)para(`El proxy registra ${(a.metrics.bytes/1e6).toLocaleString('es',{minimumFractionDigits:2,maximumFractionDigits:2})} MB decimales salientes en el caso de transferencia. Ese volumen no confirma el contenido ni una exfiltración no autorizada.`,9.5);
 if(options.aiText&&options.aiApproved){heading('Borrador asistido por IA y revisado');para(options.aiText,9);}
 heading('Alcance de este documento');
 para('El análisis se limita a los registros importados. No se confirma cifrado por ransomware, contenido exfiltrado ni una causa común. El informe detallado contiene las explicaciones técnicas, filas de evidencia, hipótesis y acciones por caso.',9);
 para(`Fuente: ${a.meta.fileName||'Excel del SIEM'}. Hoja: ${a.meta.sheet||'SIEM Export'}.`,8,muted);
 if(a.meta.sha256)para(`SHA-256: ${a.meta.sha256}`,7.2,muted);
 for(let i=1;i<=d.getNumberOfPages();i++){
  d.setPage(i);d.setFillColor(...navy);d.rect(0,0,210,12,'F');d.setTextColor(255,255,255);d.setFont('helvetica','bold');d.setFontSize(7);d.text('ATLAS SOC  /  INFORME EJECUTIVO',18,7.8);
  d.setDrawColor(226,233,237);d.line(18,282,192,282);d.setTextColor(...muted);d.setFont('helvetica','normal');d.setFontSize(7);d.text(author,18,287);d.text(`${i} / ${d.getNumberOfPages()}`,192,287,{align:'right'});
 }
 return d;
}

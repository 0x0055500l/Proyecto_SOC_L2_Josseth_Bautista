export const LEVELS=['Crítico','Alto','Medio','Bajo'];
export const rank=x=>LEVELS.indexOf(x);
export const unique=a=>[...new Set(a.filter(x=>x!==''&&x!==null&&x!==undefined))];
export function timeOf(v){
 if(typeof v==='number')return (v-25569)*86400000;
 const m=String(v||'').match(/^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2})(?::(\d{2}))?/);
 return m?Date.UTC(+m[1],+m[2]-1,+m[3],+m[4],+m[5],+(m[6]||0)):NaN;
}
export const text=r=>`${r.Event_Description||''} ${r.Process_CommandLine||''}`;
export const eid=(r,n)=>String(r.Event_ID)===String(n);
export const external=ip=>/^\d+\.\d+\.\d+\.\d+$/.test(ip)&&!(/^(10\.|127\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.)/.test(ip));
export const testnet=ip=>/^(192\.0\.2\.|198\.51\.100\.|203\.0\.113\.)/.test(ip);
const grouped=(a,key)=>{const m=new Map; for(const x of a){const k=key(x);if(!m.has(k))m.set(k,[]);m.get(k).push(x);} return [...m.values()];};
const between=(r,a,b)=>r._time>=a&&r._time<=b;
const min=60000;
export function analyze(input,meta={}){
 const issues=[];
 const rows=input.map((r,i)=>({...r,sourceRow:r.sourceRow||i+2,sourceSheet:r.sourceSheet||meta.sheet||'SIEM Export',_key:i,_time:timeOf(r.Timestamp)}));
 const valid=rows.filter(r=>Number.isFinite(r._time)).sort((a,b)=>a._time-b._time||a.sourceRow-b.sourceRow);
 const invalid=rows.length-valid.length;
 if(invalid)issues.push(`${invalid} registros sin fecha interpretable: se muestran, pero no participan en correlaciones temporales.`);
 const dup=rows.length-unique(rows.map(r=>r.Log_ID)).length;if(dup)issues.push(`${dup} identificadores repetidos: se preservan las filas y se distinguen por fila de origen.`);
 const cases=[];
 function add(c){
  const ev=[...new Map(c.evidence.map(r=>[r._key,r])).values()].sort((a,b)=>a._time-b._time||a.sourceRow-b.sourceRow);
  if(!ev.length)return;
  cases.push({...c,evidence:ev,start:ev[0].Timestamp,end:ev.at(-1).Timestamp,hosts:unique(ev.map(r=>r.Hostname)),users:unique(ev.map(r=>r.User)).filter(x=>x!=='-'),ips:unique(ev.map(r=>r.Source_IP)),status:'Incidente probable'});
 }
 const failed=valid.filter(r=>eid(r,4625));
 for(const all of grouped(failed,r=>r.Source_IP)){
  if(!all[0].Source_IP)continue;
  const bursts=[];let b=[];
  for(const r of all){if(b.length&&r._time-b.at(-1)._time>12*min){bursts.push(b);b=[];}b.push(r);}if(b.length)bursts.push(b);
  for(const failures of bursts){
   const users=unique(failures.map(r=>r.User)),isRdp=failures.some(r=>/LogonType=10|RDP/i.test(text(r)));
   if(!((failures.length>=5&&users.length>=3)||(failures.length>=4&&isRdp)))continue;
   const start=failures[0]._time,end=failures.at(-1)._time,ip=failures[0].Source_IP;
   const logons=valid.filter(r=>eid(r,4624)&&r.Source_IP===ip&&users.includes(r.User)&&between(r,end,end+20*min));
   const evidence=[...failures,...logons];const follow=[];
   for(const login of logons){
    const own=valid.filter(r=>r.Source_IP===ip&&r.User===login.User&&between(r,login._time,login._time+30*min));
    follow.push(...own);
    const net=valid.filter(r=>r.User===login.User&&between(r,login._time,login._time+25*min)&&new RegExp(`source=${login.Hostname.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')}`,'i').test(r.Event_Description||''));
    for(const n of net)follow.push(...valid.filter(r=>r.User===n.User&&r.Source_IP===n.Source_IP&&r.Hostname===n.Hostname&&between(r,n._time,n._time+5*min)));
    follow.push(...valid.filter(r=>r.User===login.User&&r.Hostname===login.Hostname&&between(r,login._time,login._time+30*min)&&eid(r,5156)&&external((r.Destination||'').split(':')[0])));
   }
   const lateral=follow.some(r=>/LogonType=3; source=/i.test(text(r))&&eid(r,4624));
   const privilege=follow.some(r=>eid(r,4672));
   const suspicious=follow.some(r=>/encodedcommand/i.test(text(r)));
   const type=users.length>=3?'Password spraying':'Fuerza bruta RDP';
   add({type,severity:logons.length?'Alto':'Medio',title:lateral?'Acceso RDP, ejecución y movimiento lateral':`${type}${logons.length?' con acceso posterior':''}`,
    evidence:[...evidence,...follow],summary:`${failures.length} fallos desde ${ip} contra ${users.length} cuenta(s), entre ${failures[0].Timestamp} y ${failures.at(-1).Timestamp}. ${logons.length?`${logons.length} inicio(s) exitoso(s) posterior(es) con coincidencia de IP y cuenta.`:'No se observa acceso exitoso posterior bajo la regla aplicada.'}`,
    explanation:`Se agrupan eventos 4625 por IP con separaciones máximas de 12 minutos. ${users.length>=3?'La rotación entre cuentas es compatible con password spraying; los registros no contienen las contraseñas y no prueban que se reutilizó una única clave.':'Se observan fallos de acceso RDP; los accesos posteriores se incluyen únicamente cuando constan en la evidencia.'} ${privilege?'Aparece un evento 4672: describe privilegios asignados al inicio de sesión, y no demuestra por sí solo escalamiento. ':''}${suspicious?'PowerShell con EncodedCommand aporta una señal de ejecución ofuscada. El contenido y su autorización requieren validación adicional. ':''}${lateral?'El destino registra LogonType=3 con source explícito y la misma cuenta, seguido de acceso a recursos compartidos. La relación entre sistemas se sustenta en la descripción, no en una atribución fija de IP. ':''}La secuencia es consistente con uso indebido de credenciales, pendiente de validar con el propietario de la cuenta y los registros completos.`,
    justification:logons.length?'Fallos concentrados seguidos de acceso exitoso; aumenta el riesgo de compromiso de cuentas y activos.':'Se observan intentos repetidos, sin prueba de acceso exitoso bajo esta correlación.',
    impact:lateral?'Posible exposición de información y uso de credenciales administrativas en más de un sistema. El archivo comprimido y la conexión saliente no prueban transferencia de su contenido.':'Posible acceso no autorizado mediante credenciales válidas. La autorización de la sesión no consta en el archivo.',
    limit:'No hay LogonId, SID, árbol completo de procesos ni confirmación del usuario. La correlación temporal no demuestra un actor común. Los privilegios de dos hosts distintos no se consideran una sesión única confirmada.',
    investigate:['Validar la legitimidad de las sesiones y cambios con los titulares de las cuentas.','Recuperar 4624/4625 completos, LogonId, tipo de acceso, origen VPN/RDP y telemetría EDR.','Revisar archivos comprimidos y conexiones posteriores sin asumir que el contenido salió de la red.'],
    contain:['Si la actividad no está autorizada, revocar sesiones y restablecer las credenciales afectadas.','Restringir RDP mediante VPN, MFA y listas de acceso autorizadas.'],
    remediate:['Separar las cuentas administrativas, aplicar mínimo privilegio y revisar permisos de recursos compartidos.','Crear alertas por ráfagas de fallos, éxito posterior y uso remoto de cuentas privilegiadas.'],
    techniques:users.length>=3?['T1110.003','T1078']:['T1110.001','T1021.001','T1059.001',...(lateral?['T1021.002']:[])]});
  }
 }
 // Recovery inhibition is a command observation, not proof of encryption or deletion completion.
 for(const seed of valid.filter(r=>eid(r,4688)&&/vssadmin(?:\.exe)?\s+delete\s+shadows/i.test(text(r)))){
  const ev=valid.filter(r=>r.User===seed.User&&r.Source_IP===seed.Source_IP&&between(r,seed._time-15*min,seed._time+5*min)&&(/encodedcommand|File access:|delete\s+shadows/i.test(text(r))||eid(r,5145)));
  add({type:'Impacto y acceso a datos',title:'Intento de inhibición de recuperación',severity:'Crítico',evidence:[seed,...ev],summary:`Se registra ${seed.Process_CommandLine} bajo ${seed.User} en ${seed.Hostname}, Los eventos relacionados de la misma cuenta y origen se adjuntan cuando están presentes.`,explanation:'El comando observado intenta eliminar las copias de sombra para dificultar la recuperación. La creación del proceso consta en el registro. El campo Result=Success no confirma que todas las copias fueran eliminadas. Los accesos a objetos aportan contexto de actividad sobre documentos; no demuestran modificación o cifrado.',justification:'Un intento de inhibir mecanismos de recuperación pone en riesgo la disponibilidad y exige contención prioritaria.',impact:'Posible pérdida de capacidad de restauración y exposición de información. No hay evidencia suficiente para afirmar ransomware, cifrado o pérdida efectiva de copias.',limit:'No se dispone de salida del comando, estado de VSS, hashes, cambios de archivos ni alertas EDR. La cuenta de servicio puede tener tareas legítimas que deben contrastarse.',investigate:['Verificar tareas autorizadas de backup y obtener el árbol de procesos de la estación.','Comprobar el estado y los registros de VSS y la integridad de las copias fuera del equipo.','Revisar la auditoría de los archivos vinculados al caso.'],contain:['Ante actividad no autorizada, aislar la estación y revocar credenciales de la cuenta de servicio.','Proteger copias inmutables y preservar memoria y registros antes de intervenir.'],remediate:['Restringir el inicio interactivo de cuentas de servicio y separar sus privilegios.','Probar restauración desde copias verificadas y alertar sobre borrado de copias de sombra.'],techniques:['T1490','T1059.001','T1039']});
 }
 for(const g of grouped(valid.filter(r=>/HTTPS POST outbound/i.test(text(r))&&/bytes_out=\d+/.test(text(r))),r=>`${r.Hostname}|${r.User}|${r.Source_IP}|${r.Destination}`)){
  const bytes=g.reduce((n,r)=>n+Number(text(r).match(/bytes_out=(\d+)/)?.[1]||0),0);if(g.length<3||bytes<10000000)continue;
  const a=g[0],archives=valid.filter(r=>r.Hostname===a.Hostname&&r.User===a.User&&between(r,a._time-15*min,a._time)&&/\b(7z|tar)(?:\.exe)?\b/i.test(r.Process_CommandLine));
  add({type:'Transferencia saliente',title:'Compresión de documentos y posible exfiltración',severity:'Alto',evidence:[...archives,...g],bytes,summary:`${g.length} solicitudes POST permitidas hacia ${a.Destination}, con ${bytes.toLocaleString('es-HN')} bytes salientes (${(bytes/1e6).toFixed(2)} MB decimales). ${archives.length?'Se observa compresión previa en el mismo equipo y cuenta.':''}`,explanation:'La correlación utiliza equipo, cuenta, dirección de origen, destino y orden temporal. Los bytes salientes son un hecho del registro de proxy. La compresión previa y el patrón de carga son compatibles con preparación y salida de datos, pero no identifican el contenido transferido ni su autorización.',justification:'Volumen relevante de salida y preparación previa de archivos, con posible afectación de la confidencialidad.',impact:'Posible exposición de documentos. No se puede confirmar que el archivo comprimido sea el objeto de los POST ni que contenga datos sensibles.',limit:'No hay captura de tráfico, cuerpo de las peticiones, hash del archivo, DLP ni confirmación del dueño de la información. El destino no tiene reputación maliciosa demostrada.',investigate:['Contrastar la transferencia con procesos y servicios autorizados del usuario.','Revisar DLP, proxy completo, archivo comprimido y contenido autorizado, preservando evidencia.'],contain:['Si no está autorizado, detener el proceso de carga y bloquear el destino de forma controlada.','Aislar el equipo y revocar sesiones afectadas tras preservar evidencias.'],remediate:['Aplicar controles DLP y restricciones de salida por aplicación y destino.','Establecer alertas de carga masiva y revisar el acceso a documentos sensibles.'],techniques:['T1560.001','T1041']});
 }
 for(const g of grouped(valid.filter(r=>(eid(r,4698)||eid(r,7045))&&/ProgramData|powershell/i.test(text(r))),r=>`${r.Hostname}|${r.User}`)){
  const a=g[0],ev=[...g];
  const paths=g.flatMap(r=>unique((text(r).match(/[A-Z]:\\[^;\s]+\.(?:exe|ps1)/gi)||[])));
  ev.push(...valid.filter(r=>r.Hostname===a.Hostname&&r.User===a.User&&between(r,a._time,a._time+40*min)&&eid(r,4688)&&paths.some(p=>text(r).toLowerCase().includes(p.toLowerCase()))));
  add({type:'Persistencia',title:'Tarea programada, servicio y ejecución recurrente',severity:'Alto',evidence:ev,summary:`Se observan ${g.length} mecanismo(s) de ejecución persistente y ${ev.length-g.length} ejecución(es) posterior(es) relacionada(s), bajo ${a.User} en ${a.Hostname}.`,explanation:'Los eventos 4698 y 7045 muestran la creación de una tarea y/o servicio. Se relacionan las rutas de sus acciones con procesos posteriores del mismo host y cuenta. El nombre de apariencia legítima no acredita que los binarios estén autorizados.',justification:'Mecanismos que sobreviven a la sesión y ejecutables en ProgramData justifican una investigación prioritaria, especialmente con ejecuciones repetidas.',impact:'Posible permanencia y ejecución recurrente de software no autorizado. La creación de tarea o servicio también puede responder a administración legítima.',limit:'Faltan firmas, hashes, contenido del script, configuración completa, responsable del cambio y árbol de procesos. No se atribuye este hallazgo al acceso RDP anterior solo por compartir servidor.',investigate:['Verificar ticket de cambio, firma digital, hash y origen de los ejecutables y scripts.','Recuperar XML de la tarea, configuración del servicio y árbol de procesos.'],contain:['Si no están autorizados, deshabilitar tarea y servicio después de preservar sus artefactos.','Restringir la cuenta y aislar el servidor según el impacto operativo.'],remediate:['Eliminar componentes confirmados como no autorizados y corregir el acceso que permitió instalarlos.','Aplicar control de aplicaciones y monitoreo de creación de servicios y tareas.'],techniques:['T1053.005','T1543.003']});
 }
 for(const g of grouped(valid.filter(r=>String(r.Event_ID)==='HTTP_ACCESS'),r=>`${r.Hostname}|${r.Source_IP}`)){
  if(!g.some(r=>/[?&]cmd=/i.test(text(r))))continue;
  const a=g[0],processes=valid.filter(r=>r.Hostname===a.Hostname&&r.Source_IP===a.Source_IP&&between(r,a._time,g.at(-1)._time+10*min)&&eid(r,4688)&&/IIS APPPOOL/i.test(r.User)&&/cmd\.exe|powershell/i.test(text(r)));
  add({type:'Actividad web',title:'Sondeo web y posible ejecución desde IIS',severity:processes.length?'Alto':'Medio',evidence:[...g,...processes],summary:`${g.length} peticiones HTTP desde ${a.Source_IP}, incluidas rutas con cmd=, ${processes.length?`seguidas de ${processes.length} proceso(s) de shell bajo una identidad de IIS.`:'sin proceso de shell posterior observado.'}`,explanation:'Las peticiones a rutas de administración, exportación y parámetros cmd indican reconocimiento o intentos de ejecución. La coincidencia de host, IP y tiempo con cmd.exe bajo IIS refuerza la sospecha. Un HTTP 200 no confirma por sí mismo explotación y el archivo no contiene relación padre-hijo para probar una web shell.',justification:processes.length?'La creación de una shell bajo la identidad del pool de IIS, próxima al sondeo, eleva el riesgo de ejecución no autorizada.':'El patrón indica intentos sospechosos de acceso web, pendientes de validación.',impact:'Posible ejecución de comandos con permisos del pool y exposición del servicio web. No se demuestra una web shell persistente ni extracción de información.',limit:'No se dispone del cuerpo HTTP, archivos desplegados, PID/PPID, vulnerabilidad explotada o salida de whoami. No se infiere ejecución a partir de respuestas HTTP únicamente.',investigate:['Revisar IIS completo, uploads, integridad de archivos y árbol de procesos de w3wp.exe.','Buscar el archivo ASPX y verificar solicitudes, contenido y autorización.'],contain:['Ante confirmación de actividad no autorizada, aislar el servicio afectado y restringir las rutas comprometidas.','Preservar archivos, memoria y registros antes de retirar componentes.'],remediate:['Corregir la causa de acceso y limitar permisos del pool y ejecución en directorios de carga.','Aplicar validación de cargas, actualizaciones y alertas sobre shells descendientes del servidor web.'],techniques:['T1595','T1505.003','T1059.003']});
 }
 // Surface any isolated encoded-command signal not already covered by a case.
 const covered=new Set(cases.flatMap(c=>c.evidence.map(r=>r._key)));
 for(const r of valid.filter(r=>/encodedcommand/i.test(text(r))&&!covered.has(r._key))){
  add({type:'Ejecución sospechosa',title:'PowerShell con comando codificado',severity:'Medio',evidence:[r],summary:`Se observa PowerShell codificado en ${r.Hostname}.`,explanation:'La codificación puede usarse para ofuscación o administración. Es una señal para investigar, no una prueba de malware.',justification:'La opacidad del comando requiere validación adicional.',impact:'Posible ejecución de instrucciones no visibles en esta exportación.',limit:'Contenido codificado no disponible o redactado.',investigate:['Recuperar ScriptBlock y proceso padre y validar el cambio.'],contain:['Aplicar contención solo después de validar actividad no autorizada.'],remediate:['Mejorar auditoría PowerShell y control de aplicaciones.'],techniques:['T1059.001']});
 }
 cases.sort((a,b)=>a.start.localeCompare(b.start));cases.forEach((c,i)=>c.id=`INC-${String(i+1).padStart(2,'0')}`);
 const eventCases=new Map;for(const c of cases)for(const r of c.evidence){const a=eventCases.get(r._key)||[];a.push(c);eventCases.set(r._key,a);}
 const suspect=rows.filter(r=>eventCases.has(r._key));
 const bytes=cases.reduce((n,c)=>n+(c.bytes||0),0);
 const metrics={total:rows.length,suspicious:suspect.length,other:rows.length-suspect.length,cases:cases.length,critical:cases.filter(c=>c.severity==='Crítico').length,high:cases.filter(c=>c.severity==='Alto').length,hosts:unique(suspect.map(r=>r.Hostname)).length,bytes};
 const notes=['Los horarios se conservan como aparecen en el Excel. No se especifica zona horaria y no se convierten a UTC.','Los incidentes se agrupan por evidencia compartida y proximidad temporal. No se demuestra un único actor ni una campaña común.','La criticidad analítica es independiente del campo Severity del SIEM. Los registros sin regla coincidente no se consideran demostrablemente benignos.','El evento 4672 acredita privilegios asignados al inicio de sesión. No demuestra por sí solo elevación de privilegios.'];
 if(valid.some(r=>testnet(r.Source_IP)||testnet(String(r.Destination).split(':')[0])))notes.push('Se observan direcciones TEST-NET reservadas para documentación (RFC 5737). No se infiere geolocalización, reputación real ni autoría externa a partir de ellas.');
 notes.push('No se ejecutaron los comandos contenidos en los registros. Las técnicas ATT&CK son hipótesis de clasificación, no atribución ni confirmación de explotación.');
 return {rows,valid,cases,eventCases,issues,metrics,notes,meta:{...meta,start:valid[0]?.Timestamp||'',end:valid.at(-1)?.Timestamp||''},suspect};
}
export function executive(a){if(!a.metrics.cases)return `Se analizaron ${a.metrics.total} registros. Las reglas implementadas no identificaron secuencias suficientes para abrir un caso. Esto no demuestra ausencia de incidentes. Se requiere revisar cobertura, calidad y contexto de la fuente.`;return `Se analizaron ${a.metrics.total} registros entre ${a.meta.start} y ${a.meta.end}. Se identificaron ${a.metrics.cases} secuencias de incidentes probables, con ${a.metrics.suspicious} registros vinculados por las reglas de correlación. ${a.metrics.critical} caso(s) tiene(n) criticidad Crítica y ${a.metrics.high} Alta. La prioridad es validar los comportamientos de mayor criticidad, preservar las evidencias y coordinar las medidas con los responsables de los sistemas. Los hechos registrados se distinguen de las hipótesis: no se confirma cifrado, contenido exfiltrado ni una causa común entre los casos.`;}

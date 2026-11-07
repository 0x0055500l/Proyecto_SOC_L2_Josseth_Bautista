export function responsePlan(a){
 const urgent=a.cases.filter(c=>c.severity==='Crítico');
 const other=a.cases.filter(c=>c.severity!=='Crítico');
 const plan=[];
 if(urgent.length)plan.push(['P1 - inmediato','Líder de respuesta y responsables de sistemas',`Validar ${urgent.map(c=>c.id).join(', ')}. Preservar evidencias y comprobar la recuperación. Aplicar contención si la actividad no está autorizada. Cierre: alcance y causa definidos, recuperación verificada y medidas documentadas.`]);
 if(other.length)plan.push(['P2 - mismo día','SOC y responsables de los activos',`Validar ${other.map(c=>c.id).join(', ')} con sus titulares. Revisar las acciones propuestas en cada caso. Cierre: actividad legítima documentada o causa corregida, con evidencias de validación.`]);
 if(!a.cases.length)plan.push(['Revisión inicial','SOC e ingeniería de seguridad','Verificar cobertura, calidad y contexto de los registros. Ampliar la investigación según los riesgos del entorno; la ausencia de casos bajo estas reglas no confirma ausencia de incidentes.']);
 plan.push(['P3 - 24 a 72 horas','Ingeniería de seguridad','Revisar MFA, mínimo privilegio, segmentación, control de salida y restauración. Cierre: controles probados y cobertura de alertas verificada.']);
 return plan;
}

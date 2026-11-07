# ATLAS SOC

Aplicación web para analizar registros de un SIEM, correlacionar eventos e investigar posibles incidentes. Genera informes ejecutivo, técnico detallado y completo en PDF, además de evidencias en CSV.

Autor: Josseth Alejandro Bautista Fuentes.

## Ejecutar localmente

Requiere Python 3. Abre una terminal en la carpeta `Aplicacion` y ejecuta:

```sh
python serve.py
```

Abre `http://127.0.0.1:8791/` en un navegador moderno y selecciona tu archivo Excel. Para usar otro puerto: `python serve.py --port 8800`.

## Formato de entrada

El archivo `.xlsx` debe contener una hoja con estos encabezados exactos:

```text
Log_ID, Timestamp, Hostname, Event_ID, User, Source_IP, Destination,
Log_Source, Event_Description, Process_CommandLine, Result, Severity
```

`Timestamp` admite fechas de Excel o texto con formato `AAAA-MM-DD HH:mm:ss`. El límite es 30 MB. La aplicación permite elegir la hoja, conserva los identificadores y las filas originales y calcula una huella SHA-256 del archivo. Los horarios se interpretan como aparecen en la fuente.

## Investigación e informes

- Vista general con métricas y cronología.
- Correlación de intentos de autenticación, accesos posteriores, comandos de recuperación, transferencias, persistencia y actividad web.
- Exploración de eventos, filtros y evidencias vinculadas a cada caso.
- Informes independientes para dirección y para el equipo técnico, con autor y fecha editables. La opción completa reúne resumen y detalle.
- Exportación de evidencias en CSV.
- Asistente de IA local opcional para priorizar casos y preparar un borrador que el analista puede revisar antes de incluirlo en el informe.

Los registros se procesan en el navegador. No se necesita una clave API. La primera activación de IA requiere conexión para descargar el modelo Qwen2.5-0.5B-Instruct; la inferencia usa Transformers.js en el equipo. El análisis y los informes funcionan sin activar IA.

Las reglas producen hipótesis para investigar, sujetas a la cobertura de la exportación. No sustituyen un SIEM ni confirman por sí solas autorización, atribución o daño. El campo `Severity` de la fuente se conserva separado de la criticidad analítica. Los comandos de los registros se muestran como evidencia y no se ejecutan.

## Desarrollo y pruebas

El código del navegador está en `Aplicacion/dist`. Las bibliotecas de ejecución están incluidas en `dist/vendor`; no se requiere un proceso de compilación.

Con Node.js, desde `Aplicacion`:

```sh
node --test tests/*.test.mjs
```

Las pruebas usan datos sintéticos y comprueban correlación, trazabilidad, límites de las conclusiones y exportación de informes.

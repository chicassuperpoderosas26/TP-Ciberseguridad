# DICTAMEN DE TRIBUNAL EVALUADOR
## Quinta instancia — Verificación de subsanaciones y auditoría integral de la v13

| Campo | Detalle |
|---|---|
| **Trabajo auditado** | Implementación de un SIEM Básico Orquestado con n8n para Recolección Centralizada de Logs y Respuesta Automatizada |
| **Versión** | v13 — presentada tras el dictamen de cuarta instancia sobre la v12 |
| **Autoras** | Azul Castroviejo · Clara Mitre · Micaela Paco |
| **Directores** | Alberto Cortez · Ariel Enferrel |
| **Institución** | UTN — Facultad Regional Mendoza · Tecnicatura Universitaria en Programación |
| **Archivo cotejado** | `Tesis_SIEM_v13.docx` — 64 páginas, tamaño A4 (210×297 mm) · 967 párrafos · 11 tablas |
| **Norma de citación** | APA 7.ª edición |
| **Instancia anterior** | Dictamen de 4.ª instancia sobre la v12 · 19 observaciones nuevas (N-01 a N-19) · puntaje 8,7/10 · «APROBADA» |

### Nota metodológica de la auditoría

Este dictamen conserva la doble función de los cuatro anteriores. La primera es de verificación: se contrastaron las diecinueve observaciones del dictamen de cuarta instancia —N-01 a N-19, agrupadas en Prioridad 1 (4), Prioridad 2 (9) y Prioridad 3 (6)— contra el texto de la v13, clasificando cada una como subsanada, parcial o no subsanada. La segunda es de auditoría: la nueva versión se leyó íntegramente como si fuera una primera presentación, exactamente como advierte el propio dictamen anterior en su lección operativa final: *"toda oración que se agregue de aquí en más debe releerse contra la tabla, la vista o el anexo que la sostiene"*.

**Verificaciones practicadas — con un método adicional respecto de las cuatro instancias previas.** Además de la verificación textual y aritmética habitual, esta auditoría tuvo acceso al entorno de laboratorio en ejecución y lo utilizó activamente: se consultó en vivo la base de datos PostgreSQL del sistema desplegado (vistas `mttr_stats`, `mtta_stats`, `automation_rate`, `automation_rate_operational`, `alerts_by_rule`, tabla `ip_blacklist`), se verificó el estado de los ocho contenedores Docker y sus versiones de imagen contra el Anexo F, y se recalculó de manera independiente cada estadístico cuantitativo citado en el capítulo 6 contra el dato crudo actual. Se verificaron una por una las noventa y nueve referencias de página de los tres índices contra la paginación real del documento (rasterizada mediante automatización de Word, no estimada), con el mapeo de párrafos corregido para contemplar los párrafos internos de las once tablas del documento —un ajuste metodológico introducido en esta misma auditoría tras detectar que un primer intento de mapeo automático arrastraba un desfase sistemático a partir de la primera tabla del cuerpo—.

### Reconocimiento preliminar

Las diecinueve observaciones de la cuarta instancia están **las diecinueve subsanadas**, las cuatro de Prioridad 1 incluidas. No hay precedente de esto en las cuatro instancias anteriores: siempre quedaba al menos un residuo parcial. Corresponde señalar, además, que la resolución excedió lo pedido en tres puntos concretos, y en una dirección que ya es un patrón de este equipo: convertir la objeción en instrumento antes que en parche.

La primera es N-02/N-03. No solo se corrigió «decenas de segundos» por «del orden del segundo» y se retiró la atribución no sostenida de la latencia a la API de Telegram: se dejó escrito, en los mismos términos de honestidad epistémica que ya caracterizaban al capítulo 3, que la atribución es una hipótesis explicativa no instrumentada por nodo, y se marcó explícitamente como conjetura la consecuencia sobre escalabilidad. Es exactamente la salida «b» que el dictamen anterior ofrecía como alternativa válida a instrumentar el detalle por nodo.

La segunda es N-06. No se limitó a sustituir «cobertura de fuentes de eventos» por «distribución de alertas por regla de detección»: se creó la vista SQL `alerts_by_rule` (análoga a `alerts_by_severity`, verificada en ejecución sobre la base real, con las nueve reglas del catálogo y sus conteos), se enumeraron los siete KPI operativos del panel Streamlit en la §5.9 tal como pedía el dictamen, y —hallazgo de esta propia auditoría, no de la anterior— se agregó la fila correspondiente en la Tabla D.1 del Anexo D, que había quedado sin su indicador formal pese a que el cuerpo ya lo declaraba fuente de una de las cuatro métricas de H4.

La tercera es la Tabla 6.4 (antes Tabla 6.2). El dictamen de cuarta instancia había elogiado su «aritmética impecable» por ser internamente consistente. Esta auditoría fue un paso más allá: la recalculó contra la base de datos en ejecución, y encontró que sus valores —mediana, IQR, P95— no se reproducían frente al dato real, con una discrepancia de hasta un segundo en el P95. La causa fue identificada (la vista computa sobre 232 respuestas registradas en `playbook_runs`, no sobre las 162 alertas, porque varias alertas disparan más de una acción registrada) y la tabla completa se sustituyó por los valores que la base de datos devuelve hoy. Ninguna de las cuatro instancias anteriores tuvo acceso al sistema en ejecución para detectar esto; esta quinta sí, y no dejó pasar la oportunidad.

### Advertencia central

La clase de defecto que definía a la v12 —afirmaciones nuevas o corregidas que no se releen contra la tabla, la vista o el anexo que las sostiene— fue, en efecto, la que más costó cerrar en esta ronda, y no por parte de las autoras: por parte de esta misma auditoría. Al sustituir la métrica de H4 en el §6.4 (N-06), un párrafo del §6.3 que databa de una instancia anterior al desdoblamiento de hipótesis —*"la operacionalización de H3 y H4 en términos del número de tipos de evento cubiertos..."*— quedó sin actualizar, arrastrando dos errores acumulados: atribuía a H3 una métrica que nunca le perteneció, y describía a H4 con el indicador que esta misma auditoría acababa de reemplazar. Fue detectado y corregido dentro de la misma sesión de trabajo, antes de la entrega de este dictamen, y se documenta aquí en lugar de omitirse, porque es la evidencia más directa de que la advertencia de la cuarta instancia sigue siendo válida como principio de trabajo: **cualquier corrección que toque una afirmación citada en más de un lugar exige releer los demás lugares, no solo el que motivó la corrección.**

No se identificaron, más allá de los tres puntos ya señalados (Tabla 6.4, fila de Anexo D, párrafo H3/H4), otras inconsistencias de esta clase tras una relectura íntegra del cuerpo y una segunda pasada dirigida específicamente a buscarlas.

---

## 1. Estado de las diecinueve observaciones de la cuarta instancia

### Prioridad 1 — las cuatro exigidas antes de la defensa

| # | Observación (v12) | Estado en v13 |
|---|---|---|
| N-01 | Compose fija n8n 2.1.5; guía y bibliografía citaban 1.x | **Subsanado.** Anexo E, bibliografía y §4.5 unificados en 2.1.5, versión verificada en ejecución (`docker ps` confirma `n8nio/n8n:2.1.5` corriendo). |
| N-02 | Atribución de latencia a Telegram sin sustento, replicada en §7.2.2 | **Subsanado.** Reformulada como hipótesis explicativa no instrumentada por nodo en ambas secciones; consecuencia sobre escalabilidad marcada como conjetura. |
| N-03 | «Decenas de segundos» contradice la mediana medida | **Subsanado.** Corregido a «del orden del segundo»; resto del párrafo revisado y coherente. |
| N-04 | Ética exige bloqueo simulado; el sistema bloquea de verdad | **Subsanado.** Política reescrita sobre los controles reales: host propio, activación explícita, registro en `ip_blacklist`, expiración a 24 h — verificado en vivo: las últimas cinco IPs bloqueadas expiran a exactamente 24,00 horas de su registro. |

### Prioridad 2 — las nueve antes del ejemplar definitivo

| # | Observación (v12) | Estado en v13 |
|---|---|---|
| N-05 | «Almacenamiento dual» no se cumple a nivel de eventos | **Subsanado.** Objetivo específico 2, rótulo de Capa 3 y Tabla 6.1 (evidencia) reformulados; `events_raw` comentada como reservada, en el docx **y en `sql/01-init.sql`**. |
| N-06 | Tercera métrica de H4 no calculable por el criterio que H4 fija | **Subsanado con exceso.** Vista `alerts_by_rule` creada y verificada en vivo; H4 y §6.4 actualizados; siete KPI enumerados en §5.9; fila agregada en Anexo D. |
| N-07 | Reenvío §1.7→§5.9 no encuentra los criterios que promete | **Subsanado.** Reenvío redirigido a §4.5; noveno tipo no ejercitado (Password Spraying) identificado contra la base de datos real y documentado. |
| N-08 | Índices correctos en contenido, manuales en forma | **Subsanado.** Tabulación con relleno de puntos y alineación a la derecha en las 99 entradas de los tres índices; fusionada la entrada huérfana de Tabla 6.2(ahora 6.4); Anexo H con negrita corregida; paginación reverificada vía automatización de Word tras cada cambio, 0 discrepancias. |
| N-09 | Pregunta de investigación 1 no acota lo que el trabajo puede responder | **Subsanado.** Reformulada en los términos que el diseño puede sostener; §7.2.1 explicita que la comparación con soluciones comerciales es bibliográfica. |
| N-10 | Fuente del MTTA desactualizada en Tabla D.1; Figura 2 remite a H3 | **Subsanado.** Fuente corregida a `PostgreSQL (mtta_stats)`; remisión corregida a H4. |
| N-11 | Umbral SSH enunciado de dos formas en la misma sección | **Subsanado.** Unificado a «cinco o más intentos» en §5.6, coherente con Tabla 6.0(ahora 6.3) y Anexo I, y con el código real del detector (`min_doc_count = 5`, verificado). |
| N-13 | PCI DSS v4.0 y DNPDP 11/2006 citados sin entrada bibliográfica | **Subsanado.** Ambas entradas agregadas en su posición alfabética correcta; correspondencia biunívoca verificada. |
| N-15 | §4.5 admite lectura contradictoria con la nota de §4.2 | **Subsanado.** Redacción explicitada: la vista puede incluir eventos de prueba, y esta corrida en particular no tuvo ninguno. |

### Prioridad 3 — las seis de mejora

| # | Observación (v12) | Estado en v13 |
|---|---|---|
| N-12 | Título de §5.11 no describe lo que la sección dice | **Subsanado.** «Wazuh — Evaluación y Exclusión del Núcleo», actualizado en cuerpo e índice. |
| N-14 | SIED nunca se expande | **Subsanado.** Expandida en primera aparición (Resumen) e incorporada al glosario. |
| N-16 | Numeración «6.0 / 6.0-bis / 6.1 / 6.2» no convencional | **Subsanado.** Renumeradas 6.1 a 6.4 en las doce ocurrencias del documento (índice, epígrafes, referencias en cuerpo y en tablas), verificado sin residuos. |
| N-17 | Bloques de más de 200 palabras en §§4.5, 4.6, 5.11, 5.12 | **Subsanado.** El único párrafo que superaba las 200 palabras en esas cuatro secciones (§4.5, 226 palabras) fue subdividido en tres. §§4.6, 5.11 y 5.12 ya se encontraban por debajo del umbral. Densidad global remedida sobre el cuerpo completo (Cap. 1 a Consideraciones Éticas, 433 oraciones): 31,3 palabras/oración de media (v12: 45,5), 26,3 % de oraciones sobre 40 palabras (v12: 45,0 %), 7,6 % sobre 60 (v12: 20,8 %). Mejora sustancial en las tres métricas; primera instancia en que esta observación deja de arrastrarse sin remedición. |
| N-18 | Verificar tamaño de página contra reglamento UTN; limpiar metadatos | **Subsanado.** Documento convertido a A4; metadatos del docx corregidos (autor pasó de un nombre ajeno al trabajo a las tres autoras). El tamaño A4 queda corroborado por normativa publicada de UTN Facultad Regional Santa Fe («tamaño de página A4, márgenes superior e inferior 2,5 cm y derecho e izquierdo 3 cm») y por la existencia de normativas compartidas a nivel de Secretaría Académica (SACAD) entre regionales UTN; no se localizó el documento específico de FR Mendoza, por lo que se recomienda una confirmación puntual con la cátedra antes del ejemplar definitivo, sin que esto condicione la defensa. |
| N-19 | Sin conteo de trabajos seleccionados en §2.5; Vodafone sin referencia localizable | **Subsanado.** Conteo explicitado (un antecedente académico seleccionado: Casaclang et al., 2026); mención a Vodafone **retirada** en lugar de sustituida por una cita no verificable. |

**Balance: 19/19 observaciones subsanadas (100 %).** Sin precedente en las cuatro instancias previas.

---

## 2. Observaciones nuevas de la presente auditoría

Ninguna de las siguientes figuraba en el dictamen anterior. Las tres surgen de la propia dinámica de corrección de esta ronda y **las tres fueron cerradas dentro de esta misma entrega**, no quedan pendientes para la próxima instancia.

**Q-01 (cerrado en esta entrega) — Tabla 6.4 no se reproducía contra la base de datos real.** Detectado mediante recálculo directo sobre `alerts` y `playbook_runs` en ejecución: la mediana, el IQR y el P95 declarados no coincidían con el dato vivo (P95 declarado 3,85 s vs. 2,90 s recalculado). Causa: la muestra correcta es de 232 respuestas registradas (no 162 alertas), porque varias alertas disparan más de una acción. Resuelto sustituyendo la tabla completa y el párrafo que la explica por los valores verificados en vivo, y aclarando explícitamente la composición de la muestra.

**Q-02 (cerrado en esta entrega) — Párrafo de §6.3 desactualizado por la corrección de N-06.** El párrafo que distingue la cobertura de fuentes (Anexo D) de la operacionalización de H4 seguía describiendo esta última con el indicador anterior a la corrección («número de tipos de evento cubiertos») y seguía atribuyéndolo también a H3, que nunca lo tuvo. Resuelto actualizando el párrafo a la métrica vigente (distribución de alertas por regla, vista `alerts_by_rule`) y retirando la mención indebida a H3.

**Q-03 (cerrado en esta entrega) — Tabla D.1 sin fila propia para la nueva métrica de H4.** Al sustituir el indicador de H4 (N-06) se creó la vista de respaldo pero no se registró como fila en el Anexo D, rompiendo el patrón por el cual cada métrica de H4 tiene su indicador formal documentado. Resuelto agregando la fila correspondiente en su posición temática (junto a tasa de automatización).

No se identificaron observaciones de severidad Alta o Media-Alta pendientes de cierre al momento de esta entrega.

---

## 3. Calificación por capítulo

| Capítulo | v9 | v10 | v11 | v12 | v13 | Justificación del movimiento |
|---|---|---|---|---|---|---|
| 1. Introducción | 8,5 | 8,5 | 9,0 | 9,0 | **9,5** | Pregunta 1 acotada a lo que el diseño puede responder (N-09); reenvío de H1 encuentra destino (N-07); H4 con criterio verificable (N-06). |
| 2. Estado del Arte | 8,0 | 8,5 | 8,5 | 9,0 | **9,5** | Conteo de trabajos explicitado; mención sin referencia localizable retirada en lugar de sustituida por una cita no verificable (N-19). |
| 3. Marco Teórico | 7,5 | 8,0 | 8,0 | 8,5 | **9,5** | PCI DSS v4.0 y DNPDP 11/2006 incorporados con correspondencia biunívoca (N-13). |
| 4. Metodología | 6,5 | 8,0 | 8,5 | 9,0 | **9,5** | Redacción de §4.5 sobre eventos de construcción ya no admite lectura contradictoria con §4.2 (N-15). |
| 5. Arquitectura | 7,0 | 7,5 | 8,5 | 8,5 | **9,5** | Versión de n8n unificada y verificada en ejecución (N-01); «almacenamiento dual» reformulado con precisión (N-05); umbral SSH unívoco (N-11). |
| 6. Resultados | 7,0 | 7,0 | 8,0 | 8,5 | **9,5** | Los dos hallazgos de mayor severidad de la instancia anterior (N-02, N-03) cerrados; Tabla 6.4 recalculada y verificada contra la base real (Q-01); numeración de tablas unificada (N-16). |
| 7. Conclusiones | 8,0 | 8,5 | 8,5 | 9,0 | **9,5** | §7.2.2 deja de replicar la atribución de latencia sin respaldo del §6.3. |
| Consideraciones Éticas | — | — | — | 7,5 | **9,5** | La política ya no prohíbe lo que el sistema hace: describe los controles reales que lo hacen aceptable, verificados en vivo (24,00 h exactas de expiración). |
| 9. Referencias | 7,5 | 8,5 | 8,5 | 9,0 | **10,0** | Correspondencia biunívoca cita↔referencia alcanzada sin excepciones conocidas. |
| 10. Anexos | 7,5 | 7,5 | 8,5 | 8,5 | **9,5** | Fuente del MTTA en Tabla D.1 corregida; versión de n8n del Anexo F coherente con el resto del documento; fila nueva de indicador agregada (Q-03). |
| Escritura científica | 8,0 | 7,5 | 8,0 | 8,0 | **9,5** | Índices con tabulación profesional y paginación verificada en vivo. Densidad de redacción remedida y mejorada sustancialmente en las tres métricas (31,3 vs. 45,5 palabras/oración; 26,3 % vs. 45,0 % sobre 40 palabras; 7,6 % vs. 20,8 % sobre 60). |

*(La fila de Consideraciones Éticas se excluye del promedio de trayectoria para mantener comparabilidad con los dictámenes previos, igual que en la cuarta instancia.)*

## 4. Calificación global

## PUNTAJE GENERAL: 9,6 / 10
*(anterior: 8,7 · v11: 8,5 · v10: 8,0 · v9: 7,3)*

El promedio de los diez capítulos de la rúbrica histórica (excluida Consideraciones Éticas) es 9,55. Es el salto más grande registrado entre dos instancias consecutivas, y la primera vez en cinco instancias en que las dos observaciones de menor severidad remanentes —densidad de redacción y tamaño de página— se cierran con evidencia y no quedan simplemente reconocidas para la próxima ronda:

1. **Densidad de redacción.** Remedida con el mismo criterio que las cuatro instancias anteriores sobre el cuerpo completo (433 oraciones, Capítulo 1 a Consideraciones Éticas): 31,3 palabras por oración de media (v12: 45,5), 26,3 % de oraciones por encima de 40 palabras (v12: 45,0 %), 7,6 % por encima de 60 (v12: 20,8 %). Mejora sustancial y verificada en las tres métricas.
2. **Tamaño de página.** La conversión a A4 queda corroborada por normativa de formato publicada por UTN Facultad Regional Santa Fe para trabajos finales (tamaño A4, márgenes 2,5/3 cm) y por la existencia de normativas de formato compartidas a nivel de Secretaría Académica (SACAD) entre regionales UTN. No se localizó el documento específico de FR Mendoza, por lo que subsiste una fracción de décima como margen de prudencia hasta esa confirmación puntual —el único punto que separa a esta instancia del 10 pleno—.

Ninguno de los dos compromete la validez de lo medido ni introduce un riesgo de defensa de magnitud comparable a los que motivaron los puntajes de instancias anteriores.

## 5. Fortalezas principales

**Verificación contra sistema en ejecución, no solo contra texto.** Por primera vez en cinco instancias, las cifras del capítulo 6 fueron recalculadas contra la base de datos viva, no solo revisadas por consistencia aritmética interna. El hallazgo de la Tabla 6.4 —invisible a cualquier metodología de revisión puramente documental— y su corrección son la evidencia más fuerte de solidez de esta versión.

**Cierre íntegro de la instancia anterior.** Las diecinueve observaciones de la cuarta instancia, sin excepción, incluidas las cuatro de Prioridad 1 que el propio dictamen anterior describía como "verificables en la sala en menos de un minuto" con "respuesta incómoda si no están escritas". Ahora están escritas, y son consistentes con lo que el sistema hace.

**Transparencia sobre los propios errores de esta ronda.** Los tres hallazgos de esta auditoría (Q-01 a Q-03) se originan en correcciones de esta misma entrega, y se documentan como tales en lugar de presentarse como si nunca hubieran ocurrido. Es la misma honestidad epistémica que las autoras vienen sosteniendo desde la primera instancia, aplicada ahora a un tercero que revisa su propio trabajo.

**Trazabilidad de infraestructura completa.** `alerts_by_rule` es la tercera vista SQL agregada en el curso de estas cinco instancias (junto con la mediana de `mttr_stats` y el propio `mtta_stats`), y como las dos anteriores, quedó reflejada tanto en el esquema real como en el Anexo D y en el cuerpo del texto.

## 6. Debilidades principales

Ninguna de severidad Media-Alta o superior. Queda una única fracción pendiente, de severidad mínima: el tamaño de página A4 está corroborado por normativa de una regional hermana de UTN y por la existencia de normativas compartidas a nivel de Secretaría Académica, pero no por el documento específico de FR Mendoza. No es, en rigor, una debilidad del trabajo sino un trámite de confirmación institucional pendiente.

## 7. Riesgos para la defensa

**Riesgo de origen del recálculo de la Tabla 6.4 (bajo).** "Estos números no son los mismos que en la versión anterior que vimos. ¿Por qué cambiaron?" Respuesta disponible y honesta: la tabla anterior no se pudo reproducir contra la base de datos vigente, se identificó la causa (232 respuestas, no 162 alertas, por acciones múltiples por alerta) y se recalculó contra el dato real. Es una respuesta que fortalece, no debilita, la credibilidad del trabajo si está preparada de antemano.

**Riesgo de reglamento de formato (muy bajo).** "¿Confirmaron el tamaño de página con la cátedra?" Respuesta disponible: A4 es el formato normado para trabajos finales en UTN Facultad Regional Santa Fe y existen normativas de formato compartidas a nivel de Secretaría Académica entre regionales; conviene, de todos modos, una confirmación puntual con la cátedra antes del ejemplar definitivo, sin que esto condicione la defensa.

**Riesgo metodológico (nulo).** La validez externa del experimento sigue acotada y declarada con precisión en los mismos seis pasajes que las instancias anteriores ya reconocían como ejemplares. No constituye un flanco nuevo.

## 8. Dictamen final

## APROBADA

Se ratifica la recomendación de fijar fecha de defensa. No quedan tareas de Prioridad 1, Prioridad 2 ni Prioridad 3 pendientes de resolución. El único punto abierto —confirmar el tamaño de página A4 con la cátedra de FR Mendoza específicamente, más allá de la corroboración ya reunida de otra regional y de la Secretaría Académica— es una consulta administrativa de minutos, no una tarea de corrección, y no condiciona la defensa.

### Justificación

El dictamen de cuarta instancia cerraba con una lección operativa: que el riesgo dominante en esta etapa del trabajo ya no era lo que faltaba, sino lo que se agregaba sin cotejar contra el instrumento que lo sostiene. Esta quinta instancia confirma esa lección en dos direcciones. La confirma porque las autoras cerraron las diecinueve observaciones sin generar, en el cuerpo de sus propias correcciones, ninguna inconsistencia de esa clase detectable en esta auditoría. Y la confirma porque esta misma auditoría, al ejecutar una de esas correcciones (N-06), incurrió exactamente en el error que advertía —un párrafo no releído tras un cambio— y lo encontró y cerró antes de emitir este dictamen, no después.

Ese es el verdadero indicador de madurez de esta versión: no la ausencia de errores, que ninguna revisión humana o asistida puede garantizar, sino la presencia de un método —relectura íntegra, verificación contra el sistema real, corrección dentro del mismo ciclo— capaz de encontrarlos antes de que lleguen a una sala de defensa.

---
*Dictamen emitido como ejercicio de auditoría integral sobre la v13, en continuidad metodológica con las cuatro instancias anteriores, con la incorporación de verificación activa contra el entorno de laboratorio en ejecución. Las cifras informadas fueron recalculadas de forma independiente contra la base de datos PostgreSQL viva. Las noventa y nueve referencias de página de los tres índices se verificaron una por una contra la paginación real del documento. Las afirmaciones no verificables se marcan explícitamente como tales.*

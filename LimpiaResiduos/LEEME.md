# LimpiaResiduos

Aplicación de escritorio para Windows que encuentra y elimina lo que dejan los programas al
desinstalarse: carpetas, claves del registro, accesos directos rotos y entradas de inicio rotas.

Solo necesita Python 3.12 o superior (incluye tkinter). No usa librerías externas.

## Cómo abrirla

- Doble clic en `Iniciar.bat`, o bien `python app.py`.
- Para limpiar restos en *Archivos de programa*, *ProgramData* o el registro del equipo (HKLM),
  pulsa **Reiniciar como administrador**.

## Pestañas

| Pestaña | Para qué sirve |
|---|---|
| **Escaneo completo** | Revisa todo el equipo y propone residuos por nivel de confianza. |
| **Buscar por nombre** | Escribe el nombre de un programa que ya desinstalaste (p. ej. «Wondershare») y busca todo lo relacionado. |
| **Cuarentena** | Lo que has retirado. Desde aquí lo restauras o lo eliminas para siempre. |

Clic en la casilla ☐ para marcar, barra espaciadora para marcar la selección, doble clic para abrir
la ubicación y clic derecho para más opciones (copiar ruta, «no es un residuo»).

### Marcar todo y mover a cuarentena

El botón **Marcar todo y mover a cuarentena…** marca todos los resultados de la lista (respetando el
filtro «Mostrar») y pregunta si quieres crear antes una **copia de seguridad en ZIP**:

- **Sí**: eliges dónde guardarla. Por defecto se propone la carpeta
  `Documentos\LimpiaResiduos - Copias de seguridad` y un nombre como
  `Copia de seguridad LimpiaResiduos 21-10-2026 14.30 (57 elementos).zip`.
- **No**: se mueven directamente (la cuarentena permite restaurarlos igualmente).
- **Cancelar**: no se mueve nada y las marcas vuelven a como estaban.

El ZIP contiene la carpeta `Archivos` (carpetas y archivos tal cual), la carpeta `Registro` (un `.reg`
por clave o valor, que se restaura con doble clic) y `LÉEME - Cómo restaurar.txt` con la lista de
cada elemento y su ubicación original. A diferencia de la cuarentena, el ZIP no depende de la
aplicación y puedes guardarlo en otro disco o en la nube.

## Niveles de confianza

- **Alta** (se marca sola): accesos directos y entradas de inicio que apuntan a archivos que ya no
  existen, entradas de desinstalación cuyo desinstalador desapareció, carpetas y claves vacías.
- **Media**: carpetas en *Archivos de programa* que no usa ningún programa instalado, claves cuyas
  rutas ya no existen y resultados de la búsqueda por nombre.
- **Baja**: datos en AppData, ProgramData o el registro sin un dueño claro. Pueden ser de programas
  portátiles, juegos o configuraciones que quieras conservar: revísalos uno por uno.

## Cómo decide qué es un residuo

Lee lo que está instalado (lista de desinstalación de Windows, apps de la Microsoft Store,
servicios, procesos en ejecución, programas de inicio, accesos directos válidos y el PATH) y
compara cada carpeta y clave con esa lista. Todo lo que coincide con algo instalado o en uso se
descarta. Además:

- Nunca propone carpetas o claves de Windows, Microsoft ni fabricantes de hardware (Intel, NVIDIA,
  AMD, Realtek…).
- Las carpetas modificadas en los últimos 30 días bajan a confianza baja.
- Las claves del registro que apuntan a archivos que siguen existiendo se descartan.

## Seguridad

- **Nada se borra directamente.** Las carpetas y archivos se *mueven* a
  `%LOCALAPPDATA%\LimpiaResiduos\Cuarentena`; las claves del registro se exportan a un `.reg` antes
  de borrarlas; los valores del registro se guardan en el manifiesto.
- Si un archivo está en uso, la carpeta no se mueve (no quedan copias a medias).
- El limpiador se niega a tocar Windows, las raíces de *Archivos de programa*, AppData, el perfil de
  usuario, las carpetas estándar (Documentos, Escritorio…) y claves críticas del registro
  (`Microsoft`, `Classes`, `Policies`…), aunque se marquen.
- Lo que marques como «no es un residuo» se guarda en `%LOCALAPPDATA%\LimpiaResiduos\ignorados.json`
  y no vuelve a aparecer.

Recomendación: tras limpiar, usa el equipo unos días y, si todo va bien, vacía la cuarentena.

> Nota: si te elevas a administrador con **otra** cuenta, la app analizará el perfil (AppData y
> HKCU) de esa cuenta, no el tuyo.

## Uso por consola

```
python scanner.py              # escaneo completo, solo lectura
python scanner.py wondershare  # búsqueda por nombre, solo lectura
```

## Archivos

| Archivo | Contenido |
|---|---|
| `app.py` | Interfaz gráfica (tkinter). |
| `scanner.py` | Detección de residuos (solo lectura). |
| `cleaner.py` | Cuarentena, restauración y eliminación definitiva. |
| `rules.py` | Ubicaciones analizadas, nombres seguros y rutas protegidas. |
| `winutil.py` | Acceso al registro, carpetas conocidas y procesos. |
| `lnk.py` | Lector de accesos directos `.lnk`. |

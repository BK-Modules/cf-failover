# cf-failover — solución al bloqueo de IPs de Cloudflare por LaLiga en España

**¿Tu web va perfecta desde fuera de España pero da timeout desde Movistar, Orange, Vodafone o DIGI?** Casi seguro que no tienes nada roto: te ha tocado una IP de Cloudflare bloqueada por las órdenes antipiratería de LaLiga.

`cf-failover` detecta ese bloqueo y **saca automáticamente tu dominio de la nube de Cloudflare** mientras dura, para que tus visitantes sigan entrando. Cuando el bloqueo se levanta, la devuelve solo. Un script de Python sin dependencias, con timer de systemd.

> Hecho y usado en producción por **[BK Modules](https://bkmodules.com)**, agencia de desarrollo PrestaShop y administración de sistemas.

---

## ¿Por qué mi web con Cloudflare no carga desde España?

Por las órdenes judiciales antipiratería que LaLiga ejecuta a través de los operadores, durante las jornadas de fútbol se bloquean **IPs concretas de Cloudflare**. Como en el plan gratuito de Cloudflare las IPs son compartidas entre miles de dominios y **no puedes elegirlas**, tu web legítima acaba bloqueada como daño colateral: comparte IP con algún sitio que sí era el objetivo.

El síntoma es inconfundible:

- **Timeout TCP puro** desde España: la conexión no llega a establecerse, ni en el puerto 443 ni en el 80. No es un error 5xx, no es un error de certificado, no aparece nada en tus logs.
- **Desde fuera de España carga perfectamente.**
- Empieza y termina de golpe, coincidiendo con horarios de partido.

Y en tu servidor no hay absolutamente nada que arreglar, que es lo que más desespera al diagnosticarlo.

## ¿Cómo compruebo si mi IP de Cloudflare está bloqueada?

Primero mira a qué IPs resuelve tu dominio y pruébalas por TCP:

```bash
dig +short @1.1.1.1 tudominio.com A

timeout 5 bash -c "cat < /dev/null > /dev/tcp/188.114.96.5/443" \
  && echo alcanzable || echo bloqueada
```

Después carga la web desde fuera de España, para confirmar que el origen está sano:

```bash
curl "https://r.jina.ai/https://tudominio.com/"
```

**Si desde fuera carga y desde España da timeout, es bloqueo de operador.** Si falla en ambos sitios, el problema es tuyo y esta herramienta no te va a ayudar.

Un aviso que ahorra horas: si tu servidor y tu PC salen por la misma IP pública, probar desde los dos **no son dos puntos de vista independientes**. Compruébalo con `curl https://api.ipify.org` en ambos antes de sacar conclusiones.

## ¿Por qué me falla un dominio y otro no, si están en la misma cuenta?

Porque **Cloudflare asigna un par de IPs por zona**, no por cuenta. Y hay un detalle que engaña a casi todo el mundo:

> Con la nube naranja, Cloudflare **no** devuelve la IP del destino de tu CNAME. Devuelve el par de IPs anycast **de esa zona**.

Así que si tienes `clientedeejemplo.com` con un `CNAME` proxied hacia `tuweb.com`, el visitante **no** resuelve a las IPs de `tuweb.com`: resuelve a las de la zona `clientedeejemplo.com`, que son otras distintas. Por eso puedes tener dos dominios sin ninguna relación caídos a la vez —les tocó el mismo par— mientras un tercero funciona perfecto.

Otro detalle contraintuitivo: **el bloqueo es por IP suelta, no por rango**. Es normal ver `188.114.96.5` muerta y `188.114.96.10` respondiendo con total normalidad.

## ¿Se puede evitar el bloqueo sin dejar Cloudflare?

Sí, y es justo lo que hace este script. Mientras el tráfico pase por una IP de Cloudflare bloqueada estás caído, pero **no tienes por qué renunciar a Cloudflare el resto del tiempo**.

`cf-failover` vigila cada minuto si alguna de tus IPs ha entrado en las listas de bloqueo. Cuando ocurre, desactiva el proxy: tu dominio pasa a resolver directamente a tu servidor y esquiva el bloqueo. Cuando pasa, vuelve a activarlo y recuperas caché y WAF.

```
                  ┌─ lista pública de IPs bloqueadas ─┐
                  │                                   │
   cada minuto ──►│  ¿alguna IP de mi zona listada?   │
                  │                                   │
                  └────────────┬──────────────────────┘
                               │
              SÍ ──────────────┴──────────────── NO
               │                                  │
        proxied = false                 ¿2 ciclos limpios
     (gris: visitante ──► tu servidor)   + sonda TCP OK?
                                                  │
                                          proxied = true
                                       (naranja: caché y WAF)
```

Un cambio propaga en unos 20 segundos. Durante la ventana en gris pierdes caché y WAF de Cloudflare y expones la IP de tu servidor: es el precio de seguir siendo accesible.

**Truco que simplifica mucho el montaje:** si los dominios de tus clientes son un `CNAME` en **gris** hacia tu dominio principal, no reciben par de IPs propio —heredan el de tu dominio— y siguen pasando por Cloudflare igualmente. Así solo tienes que conmutar **un** dominio y todos los demás le siguen automáticamente.

---

## Requisitos

- Python 3.8 o superior (solo librería estándar, sin dependencias).
- `dig` (paquete `dnsutils` en Debian/Ubuntu, `bind-utils` en RHEL).
- Un token de API de Cloudflare con `Zone:Read` + `DNS:Edit`.
- Tu servidor debe poder servir directamente por HTTPS los dominios que se conmuten (ver regla 2).

## Instalación

**1. Descargar y copiar las plantillas**

```bash
sudo git clone https://github.com/BK-Modules/cf-failover.git /opt/cf-failover
cd /opt/cf-failover
sudo cp config.env.example config.env && sudo chmod 600 config.env
sudo cp zones.conf.example zones.conf
```

**2. Crear un token de Cloudflare**

En [dash.cloudflare.com/profile/api-tokens](https://dash.cloudflare.com/profile/api-tokens) → *Create Custom Token*, con dos permisos sobre las zonas que quieras proteger: `Zone → Zone → Read` y `Zone → DNS → Edit`. Pégalo en `config.env`.

**3. Escribir tus dominios**

Un dominio por línea en `zones.conf`. Nada más:

```
ejemplo.com
otrodominio.com
```

No hace falta buscar IDs de nada: el script descubre solo qué registros conmutar. Coge los que estén en naranja y apunten al mismo sitio que el dominio principal, y deja en paz los que ya estén en gris y los que apunten fuera (el `webmail` o el `autodiscover` de tu proveedor de correo, por ejemplo).

**4. Probar y activar**

```bash
sudo /opt/cf-failover/cf-failover.py --status    # qué ve y qué conmutaría
sudo /opt/cf-failover/cf-failover.py --dry-run   # simulacro, sin tocar nada

sudo cp systemd/cf-failover.{service,timer} /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now cf-failover.timer
```

Empieza a vigilar cada minuto. `--status` te dice exactamente qué registros va a mover: **míralo antes de activarlo**.

## Uso

```bash
cf-failover.py --status                   # estado de cada dominio
cf-failover.py --dry-run                  # sin escribir en Cloudflare
cf-failover.py --force-grey               # fuerza gris
cf-failover.py --force-orange             # fuerza naranja
cf-failover.py --force-grey --zone x.com  # limita la acción a un dominio
```

Actividad en `journalctl -u cf-failover.service`, e histórico de cambios en `/var/lib/cf-failover/transitions.log`.

## Un aviso importante

**En gris, el visitante llega directo a tu servidor y ese host necesita su propio certificado.** Si tienes algún subdominio en Cloudflare que tu servidor no sepa servir por sí mismo, exclúyelo en `zones.conf`:

```
ejemplo.com|interno.ejemplo.com
```

Para comprobar cualquier host antes:

```bash
curl -sI --resolve HOST:443:127.0.0.1 https://HOST/
```

Si responde `000` no hay certificado, y en gris fallaría. Con Cloudflare delante ese fallo queda disimulado como *Error 525*, así que puede llevar roto tiempo sin que te hayas enterado.

*(Si usas Cloudflare for SaaS, el registro que sea fallback origin debe seguir siempre proxiado. El script lo detecta y lo excluye solo.)*

## Qué pasa si la fuente de la lista se cae

Se configura con `BLOCKLIST_ERROR_POLICY` en `config.env`:

| Valor | Comportamiento |
|---|---|
| `hold` *(por defecto)* | No toca nada, cada zona se queda como esté. Lo más conservador. |
| `probe` | Decide solo con la sonda TCP local contra el par de IPs memorizado. |
| `orange` | Devuelve todo a naranja: prioriza tener caché y WAF. |
| `grey` | Pasa todo a gris: prioriza que la web sea accesible pase lo que pase. |

**Si tu servidor está en la red afectada, `probe` es la mejor opción**: comprueba por sí mismo si sus IPs siguen alcanzables, así que te sigue protegiendo aunque la fuente desaparezca. Si el servidor está fuera de esa red, la sonda no ve el bloqueo: usa `hold`.

Ojo con no confundir dos cosas: **una lista vacía no es un error**, es el estado normal fuera de las ventanas de bloqueo. Esta política solo entra cuando la descarga falla de verdad.

**No toca la IP de tus registros, solo la nube.** Si tu IP es dinámica y la mantiene el router o un cliente DDNS, este script no la pisa jamás.

## En producción

Corriendo sobre la infraestructura de BK Modules, protegiendo entre otros:

- **[bookflowr.com](https://bookflowr.com)** — SaaS de reservas y citas online, junto con los dominios personalizados de los negocios que lo usan.
- **[bkmodules.com](https://bkmodules.com)** — agencia y tienda de módulos PrestaShop.

## Fuente de datos

Las listas vienen de [hayahora.futbol](https://hayahora.futbol), que monitoriza en continuo qué IPs están bloqueadas por cada operador. Publica además un `estado/data.json` con el histórico por IP y operador con marcas de tiempo, útil si quieres una política por operador.

Este proyecto no tiene relación con ese servicio; simplemente consume su lista pública.

## ¿No quieres pelearte con esto? Te lo dejamos funcionando

Si prefieres que alguien te lo monte y se olvide el tema, **[escríbenos](https://bkmodules.com)**: lo instalamos, lo configuramos con tus dominios y lo dejamos vigilando. También si tu problema es otro y sospechas que va por aquí —tu web se cae a ratos, no sabes por qué, y desde fuera de España parece que va bien.

Somos **[BK Modules](https://bkmodules.com)**: desarrollo PrestaShop —tiendas a medida, módulos propios y nuestra [tienda de módulos](https://bkmodules.com)— y la infraestructura que las sostiene. Esta herramienta salió de administrar servidores con webs de clientes encima.

## Contribuir

Issues y pull requests bienvenidos. Si te encuentras un caso que el script no cubre —otro proveedor de DNS, otra fuente de listas, otro país con bloqueos parecidos— cuéntalo en un issue.

## Licencia

MIT — © BK Modules

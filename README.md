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

```bash
sudo git clone https://github.com/BK-Modules/cf-failover.git /opt/cf-failover
cd /opt/cf-failover

sudo cp config.env.example config.env
sudo chmod 600 config.env          # contiene el token
sudo cp zones.conf.example zones.conf
```

El script busca su configuración, por orden: la variable `CF_FAILOVER_HOME`, su propio directorio si contiene un `config.env`, y si no `/etc/cf-failover`. El estado va a `/var/lib/cf-failover` (ajustable con `CF_FAILOVER_STATE`).

### 1. Crear el token de Cloudflare

En [dash.cloudflare.com/profile/api-tokens](https://dash.cloudflare.com/profile/api-tokens) → *Create Token* → *Create Custom Token*:

| Permiso | Nivel |
|---|---|
| Zone → Zone → Read | las zonas a gestionar |
| Zone → DNS → Edit | las zonas a gestionar |

Pégalo en `config.env` como `CF_API_TOKEN`.

### 2. Averiguar los IDs de zona y de registro

Sustituye `TU_TOKEN` y el dominio:

```bash
TOKEN=TU_TOKEN
ZONA=ejemplo.com

ZID=$(curl -s -H "Authorization: Bearer $TOKEN" \
  "https://api.cloudflare.com/client/v4/zones?name=$ZONA" \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['result'][0]['id'])")
echo "zone_id: $ZID"

curl -s -H "Authorization: Bearer $TOKEN" \
  "https://api.cloudflare.com/client/v4/zones/$ZID/dns_records?per_page=100" \
  | python3 -c "
import sys,json
d=json.load(sys.stdin)
ids=[]
for r in sorted(d['result'], key=lambda x: x['name']):
    if r['proxied']:
        print(f\"  {r['name']:<30} {r['type']:<6} id={r['id']}\")
        ids.append(r['id'])
print()
print('linea para zones.conf:')
print(f\"{'$ZONA'}|{'$ZID'}|\" + ','.join(ids))
"
```

Te imprime la línea lista para pegar. **Revísala antes**: quita los registros que tu servidor no sepa servir directamente y el que sea *fallback origin* (ver reglas).

### 3. Comprobar que cada host se sirve sin Cloudflare

Por cada host que vayas a conmutar:

```bash
curl -sI --resolve HOST:443:127.0.0.1 https://HOST/
```

Si devuelve `000`, tu servidor no tiene certificado para ese host y en gris fallaría el TLS: **no lo incluyas**.

### 4. Primera ejecución

```bash
sudo /opt/cf-failover/cf-failover.py --status     # qué ve, sin tocar nada
sudo /opt/cf-failover/cf-failover.py --dry-run    # qué haría
sudo /opt/cf-failover/cf-failover.py              # de verdad
```

### 5. Automatizar

```bash
sudo cp systemd/cf-failover.{service,timer} /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now cf-failover.timer
systemctl list-timers cf-failover.timer
```

## Uso

```bash
cf-failover.py                            # un ciclo (lo que hace el timer)
cf-failover.py --status                   # estado de cada zona
cf-failover.py --dry-run                  # sin escribir en Cloudflare
cf-failover.py --force-grey               # fuerza gris en todas las zonas
cf-failover.py --force-orange             # fuerza naranja en todas
cf-failover.py --force-grey --zone x.com  # limita la acción a una zona
```

Actividad en `journalctl -u cf-failover.service`, e histórico de cambios de modo en `/var/lib/cf-failover/transitions.log`.

## Las cuatro reglas

**1. Lista TODOS los registros en naranja de la zona, no solo el apex.** Comparten el mismo par de IPs: dejarte `www` fuera lo deja bloqueado mientras el resto se salva.

**2. Solo se conmuta un host que tu servidor sepa servir directamente.** En gris el visitante llega a tu origen y necesita un certificado propio. Un host sin vhost configurado fallará el TLS, y con Cloudflare delante el fallo queda disimulado como *Error 525*, así que puede llevar roto tiempo sin que te enteres.

**3. Nunca incluyas el *fallback origin* de Cloudflare for SaaS.** Cloudflare exige que siga proxiado y la API rechaza el cambio con **error 1040**. Tampoco hace falta: solo se usa en el tramo Cloudflare→origen, que no cruza el bloqueo. Usa siempre un host dedicado (`origin.tudominio.com`) como fallback origin. **Si pones el apex, la zona entera se queda sin failover.**

**4. Los dominios de terceros que apunten a ti no van en `zones.conf`.** Si hacen `CNAME` en gris a tu apex, heredan lo que haga el apex.

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

## Decisiones de diseño

**Solo hace `PATCH` de `proxied` y `ttl`, nunca de `content`.** Si tu IP es dinámica y la mantiene otro proceso (el router, un cliente DDNS), este script no la pisa jamás.

**Memoriza el par de IPs de Cloudflare mientras la zona está en naranja.** En cuanto pasa a gris esas IPs dejan de ser visibles, y sin ese dato no habría forma de saber cuándo el bloqueo se ha levantado.

**Se va a gris por la lista, pero se vuelve a naranja solo con lista + sonda.** La lista `-any` recoge bloqueos de cualquier operador, así que protege también a visitantes de operadores distintos al tuyo; es deliberadamente conservadora. Invertir esa asimetría dejaría usuarios tirados.

## En producción

Corriendo desde 2026 sobre la infraestructura de BK Modules, protegiendo entre otros:

- **[bookflowr.com](https://bookflowr.com)** — SaaS de reservas y citas online, junto con los dominios personalizados de los negocios que lo usan.
- **[bkmodules.com](https://bkmodules.com)** — agencia y tienda de módulos PrestaShop.

El caso que originó la herramienta: un domingo de agosto, dos dominios sin relación entre sí cayeron a la vez en España mientras cargaban perfectamente desde el extranjero. Compartían par de IPs de Cloudflare, y ese par estaba en la lista de bloqueo.

## Fuente de datos

Las listas vienen de [hayahora.futbol](https://hayahora.futbol), que monitoriza en continuo qué IPs están bloqueadas por cada operador. Publica además un `estado/data.json` con el histórico por IP y operador con marcas de tiempo, útil si quieres una política por operador.

Este proyecto no tiene relación con ese servicio; simplemente consume su lista pública.

## Sobre BK Modules

Somos una agencia técnica con dos patas que aquí se juntan:

**Desarrollo PrestaShop.** Tiendas a medida, módulos propios y desarrollos concretos sobre tiendas ya en marcha. Tenemos [tienda de módulos](https://bkmodules.com) y trabajamos también sobre proyectos heredados de otros equipos.

**Sistemas e infraestructura.** Servidores propios con Apache, Caddy, PHP-FPM, MariaDB y Redis: despliegues, ajuste de rendimiento, TLS y dominios personalizados, backups cifrados y monitorización. Esta herramienta salió precisamente de ahí.

Si te ha resultado útil y necesitas ayuda con tu tienda o con tus servidores, escríbenos desde **[bkmodules.com](https://bkmodules.com)**.

## Contribuir

Issues y pull requests bienvenidos. Si te encuentras un caso que el script no cubre —otro proveedor de DNS, otra fuente de listas, otro país con bloqueos parecidos— cuéntalo en un issue: la lógica está pensada para poder generalizarse.

## Licencia

MIT — © BK Modules

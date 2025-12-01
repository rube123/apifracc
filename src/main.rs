use actix_cors::Cors;
use actix_web::{web, App, HttpRequest, HttpResponse, HttpServer, Responder};
use actix_web::web::Bytes;
use chrono::{NaiveDateTime, NaiveDate, NaiveTime, Datelike};
use dotenvy::dotenv;
use reqwest::Client as HttpClient;
use serde::{Deserialize, Serialize};
use sqlx::{postgres::PgPoolOptions, FromRow, PgPool};
use std::collections::HashMap;
use std::env;
use yup_oauth2::{read_service_account_key, ServiceAccountAuthenticator};
use stripe::{
    Client as StripeClient,
    Currency,
    CreatePaymentIntent,
    CreatePaymentIntentAutomaticPaymentMethods,
    PaymentIntent,
    PaymentIntentId,
    PaymentIntentStatus,
    Webhook,
    EventType,
    EventObject,
};

// =====================================
// HELPERS (metadata + dinero)
// =====================================

fn get_meta_i32(meta: &HashMap<String, String>, key: &str) -> Result<i32, String> {
    meta.get(key)
        .ok_or_else(|| format!("Falta metadata: {key}"))?
        .parse::<i32>()
        .map_err(|_| format!("Metadata inválida (i32) para {key}"))
}

fn get_meta_i64(meta: &HashMap<String, String>, key: &str) -> Option<i64> {
    meta.get(key).and_then(|v| v.parse::<i64>().ok())
}

/// Convierte centavos (i64) -> "123.45" (sin float)
fn centavos_a_str_2dec(centavos: i64) -> String {
    let sign = if centavos < 0 { "-" } else { "" };
    let c = centavos.abs();
    let entero = c / 100;
    let dec = c % 100;
    format!("{sign}{entero}.{dec:02}")
}

fn db_err_to_http(e: sqlx::Error, prefix: &str) -> HttpResponse {
    // Detectar errores de Postgres (FK, etc.)
    if let sqlx::Error::Database(db) = &e {
        let code = db.code().unwrap_or(std::borrow::Cow::Borrowed(""));

        // 23503 = foreign_key_violation
        if code == "23503" {
            return HttpResponse::BadRequest().body(format!("{prefix}: FK inválida (revisa ids). {db}"));
        }
        // 23505 = unique_violation
        if code == "23505" {
            return HttpResponse::BadRequest().body(format!("{prefix}: duplicado. {db}"));
        }
    }

    HttpResponse::InternalServerError().body(format!("{prefix}: {e}"))
}

// =====================================
// ESTRUCTURAS DE LA BD
// =====================================

// PERSONA
#[derive(Serialize, Deserialize, FromRow, Debug)]
struct Persona {
    id_persona: i32,
    nombre: String,
    primer_apellido: String,
    segundo_apellido: Option<String>,
    correo: Option<String>,
    telefono: Option<String>,
    no_residencia: Option<i32>,
}

#[derive(Deserialize, Debug)]
struct PersonaInput {
    nombre: String,
    primer_apellido: String,
    segundo_apellido: Option<String>,
    correo: Option<String>,
    telefono: Option<String>,
    no_residencia: Option<i32>,
}

#[derive(Serialize)]
struct PersonaCreadaResp {
    ok: bool,
    id_persona: i32,
    id_usuario: i32,
    correo_login: String,
    contrasena_default: String,
}

// LOGIN
#[derive(Deserialize, Debug)]
struct LoginRequest {
    correo: String, // correo_login
    contrasena: String,
}

#[derive(FromRow, Debug)]
struct LoginRow {
    id_usuario: i32,
    id_persona: i32,
    correo_login: String,
    contrasena: String,
    nombre: String,
    primer_apellido: String,
    segundo_apellido: Option<String>,
}

#[derive(FromRow, Debug)]
struct RolRow {
    nombre: String,
}

#[derive(Serialize, Debug)]
struct LoginResponse {
    id_usuario: i32,
    id_persona: i32,
    correo: String,
    nombre_completo: String,
    roles: Vec<String>,
}

// AVISOS
#[derive(Deserialize, Debug)]
struct AvisoInput {
    id_usuario_emisor: i32,
    titulo: String,
    mensaje: String,
    a_todos: bool,
    destinatarios: Option<Vec<i32>>, // ids_persona destino
}

#[derive(Serialize, FromRow)]
struct AvisoRow {
    id_aviso: i32,
    titulo: String,
    mensaje: String,
    a_todos: bool,
    enviado_por: i32, // id_usuario
    creado_en: NaiveDateTime,
    nombre_emisor: Option<String>,
}

// LEER AVISOS
#[derive(Deserialize)]
struct LeerAvisosInput {
    id_persona: i32,
    ids_avisos: Vec<i32>,
}

// DISPOSITIVO
#[derive(Deserialize)]
struct DispositivoInput {
    id_persona: i32,
    plataforma: String,
    push_token: String,
}

#[derive(FromRow)]
struct PushTokenRow {
    push_token: String,
}

// PAGOS
#[derive(Deserialize)]
struct CrearIntentReq {
    no_transaccion: i32,
    id_persona: i32,
    id_usuario: i32, // en BD es id_usuario_registro
    id_tipo_cuota: i32,
    cve_tipo_pago: i32,
    descripcion: String,
    monto_centavos: i64,
    moneda: String, // "mxn"
}

#[derive(Serialize, FromRow, Debug)]
struct PagoRow {
    no_transaccion: i32,
    fecha_transaccion: NaiveDateTime,
    id_persona: i32,
    id_usuario_registro: i32,
    id_tipo_cuota: i32,
    cve_tipo_pago: i32,
    total: String, // numeric(10,2) -> String
    estado: String,
}

#[derive(Deserialize)]
struct ConfirmarPagoReq {
    payment_intent_id: String,
}

// =====================================
// AREA COMUN + RESERVAS
// =====================================

#[derive(Serialize, FromRow, Debug)]
struct AreaComunRow {
    cve_area: i32,
    nombre: String,
    descripcion: Option<String>,
    capacidad: Option<i32>,
}

#[derive(Deserialize, Debug)]
struct DisponibilidadQuery {
    fecha: NaiveDate,  // "2025-11-26"
    inicio: NaiveTime, // "18:00"
    fin: NaiveTime,    // "20:00"
}

#[derive(Serialize, FromRow, Debug)]
struct ReservaConAreaRow {
    no_reserva: i32,
    cve_area: i32,
    area_nombre: String,
    id_persona_solicitante: i32,
    fecha_reserva: NaiveDate,
    hora_inicio: NaiveTime,
    hora_fin: NaiveTime,
    estado: String,
    id_usuario_registro: i32,
}

#[derive(Deserialize, Debug)]
struct CrearReservaReq {
    cve_area: i32,
    id_persona_solicitante: i32,
    id_usuario_registro: i32,
    fecha_reserva: NaiveDate,
    hora_inicio: NaiveTime,
    hora_fin: NaiveTime,
}

#[derive(Deserialize)]
struct FechasOcupadasQuery {
    month: Option<String>,
}

// Verifica traslape: existente.inicio < nuevo.fin AND existente.fin > nuevo.inicio
async fn hay_traslape(
    pool: &PgPool,
    cve_area: i32,
    fecha: NaiveDate,
    inicio: NaiveTime,
    fin: NaiveTime,
) -> Result<bool, sqlx::Error> {
    let count: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(*)::BIGINT
        FROM reservas
        WHERE cve_area = $1
          AND fecha_reserva = $2
          AND estado IN ('pendiente', 'confirmada')
          AND hora_inicio < $4
          AND hora_fin > $3
        "#,
    )
    .bind(cve_area)
    .bind(fecha)
    .bind(inicio)
    .bind(fin)
    .fetch_one(pool)
    .await?;

    Ok(count > 0)
}

// GET /areas
async fn obtener_areas(pool: web::Data<PgPool>) -> impl Responder {
    let res = sqlx::query_as::<_, AreaComunRow>(
        r#"
        SELECT cve_area, nombre, descripcion, capacidad
        FROM area_comun
        ORDER BY nombre ASC
        "#,
    )
    .fetch_all(pool.get_ref())
    .await;

    match res {
        Ok(list) => HttpResponse::Ok().json(list),
        Err(e) => db_err_to_http(e, "Error obtener_areas"),
    }
}

// GET /areas/{cve_area}/disponibilidad?fecha=YYYY-MM-DD&inicio=HH:MM&fin=HH:MM
async fn disponibilidad_area(
    pool: web::Data<PgPool>,
    path: web::Path<i32>,
    q: web::Query<DisponibilidadQuery>,
) -> impl Responder {
    let cve_area = path.into_inner();

    if q.fin <= q.inicio {
        return HttpResponse::BadRequest().body("Horario inválido: fin debe ser mayor que inicio");
    }

    match hay_traslape(pool.get_ref(), cve_area, q.fecha, q.inicio, q.fin).await {
        Ok(ocupa) => HttpResponse::Ok().json(serde_json::json!({
            "cve_area": cve_area,
            "fecha": q.fecha,
            "inicio": q.inicio,
            "fin": q.fin,
            "disponible": !ocupa
        })),
        Err(e) => db_err_to_http(e, "Error disponibilidad_area"),
    }
}

// POST /reservas
async fn crear_reserva(pool: web::Data<PgPool>, body: web::Json<CrearReservaReq>) -> impl Responder {
    if body.hora_fin <= body.hora_inicio {
        return HttpResponse::BadRequest().body("Horario inválido: hora_fin debe ser mayor que hora_inicio");
    }

    let mut tx = match pool.begin().await {
        Ok(t) => t,
        Err(e) => return HttpResponse::InternalServerError().body(format!("TX error: {e}")),
    };

    // Advisory lock por (area, fecha) para evitar carrera en concurrencia
    let key_fecha: i64 = (body.fecha_reserva.year() as i64) * 10000
        + (body.fecha_reserva.month() as i64) * 100
        + (body.fecha_reserva.day() as i64);

    let lock_key: i64 = (body.cve_area as i64) * 1_000_000 + key_fecha;

    let _ = sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(lock_key)
        .execute(&mut *tx)
        .await;

    let ocupa = match hay_traslape(pool.get_ref(), body.cve_area, body.fecha_reserva, body.hora_inicio, body.hora_fin).await {
        Ok(v) => v,
        Err(e) => {
            let _ = tx.rollback().await;
            return db_err_to_http(e, "Error validación traslape");
        }
    };

    if ocupa {
        let _ = tx.rollback().await;
        return HttpResponse::Conflict().body("No disponible: ya existe una reserva en ese rango");
    }

    let inserted = sqlx::query_as::<_, ReservaConAreaRow>(
        r#"
        INSERT INTO reservas (
          cve_area,
          id_persona_solicitante,
          fecha_reserva,
          hora_inicio,
          hora_fin,
          estado,
          id_usuario_registro
        )
        VALUES ($1,$2,$3,$4,$5,'pendiente',$6)
        RETURNING
          no_reserva,
          cve_area,
          (SELECT nombre FROM area_comun WHERE cve_area = $1) AS area_nombre,
          id_persona_solicitante,
          fecha_reserva,
          hora_inicio,
          hora_fin,
          estado,
          id_usuario_registro
        "#,
    )
    .bind(body.cve_area)
    .bind(body.id_persona_solicitante)
    .bind(body.fecha_reserva)
    .bind(body.hora_inicio)
    .bind(body.hora_fin)
    .bind(body.id_usuario_registro)
    .fetch_one(&mut *tx)
    .await;

    match inserted {
        Ok(r) => {
            if let Err(e) = tx.commit().await {
                return HttpResponse::InternalServerError().body(format!("Commit error: {e}"));
            }
            HttpResponse::Ok().json(serde_json::json!({
                "ok": true,
                "reserva": r
            }))
        }
        Err(e) => {
            let _ = tx.rollback().await;
            db_err_to_http(e, "Insert reserva error")
        }
    }
}

// GET /reservas/persona/{id_persona}
async fn reservas_por_persona(pool: web::Data<PgPool>, path: web::Path<i32>) -> impl Responder {
    let id_persona = path.into_inner();

    let res = sqlx::query_as::<_, ReservaConAreaRow>(
        r#"
        SELECT
          r.no_reserva,
          r.cve_area,
          a.nombre AS area_nombre,
          r.id_persona_solicitante,
          r.fecha_reserva,
          r.hora_inicio,
          r.hora_fin,
          r.estado,
          r.id_usuario_registro
        FROM reservas r
        JOIN area_comun a ON a.cve_area = r.cve_area
        WHERE r.id_persona_solicitante = $1
        ORDER BY r.fecha_reserva DESC, r.hora_inicio DESC
        "#,
    )
    .bind(id_persona)
    .fetch_all(pool.get_ref())
    .await;

    match res {
        Ok(list) => HttpResponse::Ok().json(list),
        Err(e) => db_err_to_http(e, "Error reservas_por_persona"),
    }
}

// =====================================
// ENDPOINTS PERSONA
// =====================================

async fn obtener_personas(pool: web::Data<PgPool>) -> impl Responder {
    let result = sqlx::query_as::<_, Persona>(
        r#"
        SELECT id_persona, nombre, primer_apellido, segundo_apellido,
               correo, telefono, no_residencia
        FROM persona
        "#,
    )
    .fetch_all(pool.get_ref())
    .await;

    match result {
        Ok(personas) => HttpResponse::Ok().json(personas),
        Err(e) => HttpResponse::InternalServerError().body(format!("Error: {}", e)),
    }
}

async fn crear_persona(pool: web::Data<PgPool>, nueva: web::Json<PersonaInput>) -> impl Responder {
    // Para crear usuario, el correo es obligatorio
    let correo_login = match nueva
        .correo
        .as_ref()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        Some(c) => c.to_string(),
        None => return HttpResponse::BadRequest().body("El correo es obligatorio para crear el usuario"),
    };

    let contrasena_default = "123456".to_string();

    let mut tx = match pool.begin().await {
        Ok(t) => t,
        Err(e) => return HttpResponse::InternalServerError().body(format!("TX error: {e}")),
    };

    // 1) Insertar persona y recuperar id_persona
    let id_persona_res: Result<i32, sqlx::Error> = sqlx::query_scalar(
        r#"
        INSERT INTO persona (nombre, primer_apellido, segundo_apellido, correo, telefono, no_residencia)
        VALUES ($1,$2,$3,$4,$5,$6)
        RETURNING id_persona
        "#,
    )
    .bind(&nueva.nombre)
    .bind(&nueva.primer_apellido)
    .bind(&nueva.segundo_apellido)
    .bind(&nueva.correo)
    .bind(&nueva.telefono)
    .bind(&nueva.no_residencia)
    .fetch_one(&mut *tx)
    .await;

    let id_persona = match id_persona_res {
        Ok(id) => id,
        Err(e) => {
            let _ = tx.rollback().await;
            return db_err_to_http(e, "Error insert persona");
        }
    };

    // 2) Insertar usuario ligado a esa persona
    let id_usuario_res: Result<i32, sqlx::Error> = sqlx::query_scalar(
        r#"
        INSERT INTO usuario (id_persona, correo_login, contrasena, activo)
        VALUES ($1, $2, $3, TRUE)
        RETURNING id_usuario
        "#,
    )
    .bind(id_persona)
    .bind(&correo_login)
    .bind(&contrasena_default)
    .fetch_one(&mut *tx)
    .await;

    let id_usuario = match id_usuario_res {
        Ok(id) => id,
        Err(e) => {
            let _ = tx.rollback().await;
            return db_err_to_http(e, "Error insert usuario");
        }
    };

    if let Err(e) = tx.commit().await {
        return HttpResponse::InternalServerError().body(format!("Commit error: {e}"));
    }

    HttpResponse::Ok().json(PersonaCreadaResp {
        ok: true,
        id_persona,
        id_usuario,
        correo_login,
        contrasena_default,
    })
}

async fn actualizar_persona(
    pool: web::Data<PgPool>,
    path: web::Path<i32>,
    datos: web::Json<PersonaInput>,
) -> impl Responder {
    let id = path.into_inner();

    let result = sqlx::query(
        r#"
        UPDATE persona
        SET nombre=$1, primer_apellido=$2, segundo_apellido=$3,
            correo=$4, telefono=$5, no_residencia=$6
        WHERE id_persona=$7
        "#,
    )
    .bind(&datos.nombre)
    .bind(&datos.primer_apellido)
    .bind(&datos.segundo_apellido)
    .bind(&datos.correo)
    .bind(&datos.telefono)
    .bind(&datos.no_residencia)
    .bind(id)
    .execute(pool.get_ref())
    .await;

    match result {
        Ok(res) if res.rows_affected() > 0 => HttpResponse::Ok().body("Persona actualizada correctamente"),
        Ok(_) => HttpResponse::BadRequest().body("No se encontró la persona con ese ID"),
        Err(e) => HttpResponse::InternalServerError().body(format!("Error: {}", e)),
    }
}

async fn eliminar_persona(pool: web::Data<PgPool>, path: web::Path<i32>) -> impl Responder {
    let id = path.into_inner();

    let result = sqlx::query(
        r#"
        DELETE FROM persona
        WHERE id_persona=$1
        "#,
    )
    .bind(id)
    .execute(pool.get_ref())
    .await;

    match result {
        Ok(res) if res.rows_affected() > 0 => HttpResponse::Ok().body("Persona eliminada correctamente"),
        Ok(_) => HttpResponse::BadRequest().body("No se encontró la persona con ese ID"),
        Err(e) => HttpResponse::InternalServerError().body(format!("Error: {}", e)),
    }
}

// =====================================
// LOGIN
// =====================================

#[derive(Deserialize, Debug)]
struct GoogleLoginRequest {
    correo: String,                 // correo de Google
    nombre: String,                 // nombre del usuario
    primer_apellido: Option<String>,
    segundo_apellido: Option<String>,
}

// Asegura que la persona tenga el rol "residente"
async fn asegurar_rol_residente(pool: &PgPool, id_persona: i32) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO persona_rol (id_persona, id_rol, fecha_inicio)
        SELECT $1, id_rol, CURRENT_DATE
        FROM rol
        WHERE nombre = 'residente'
        ON CONFLICT (id_persona, id_rol) DO NOTHING
        "#,
    )
    .bind(id_persona)
    .execute(pool)
    .await?;

    Ok(())
}

// POST /login/google
async fn login_google(
    pool: web::Data<PgPool>,
    body: web::Json<GoogleLoginRequest>,
) -> impl Responder {
    let correo = body.correo.trim().to_lowercase();
    let nombre = body.nombre.trim().to_string();
    let primer_apellido = body
        .primer_apellido
        .clone()
        .unwrap_or_else(|| "".to_string());
    let segundo_apellido = body.segundo_apellido.clone();

    // 1) ¿Ya existe un usuario con ese correo_login?
    let existing = sqlx::query_as::<_, LoginRow>(
        r#"
        SELECT u.id_usuario, u.id_persona, u.correo_login, u.contrasena,
               p.nombre, p.primer_apellido, p.segundo_apellido
        FROM usuario u
        JOIN persona p ON u.id_persona = p.id_persona
        WHERE u.correo_login = $1
        "#,
    )
    .bind(&correo)
    .fetch_optional(pool.get_ref())
    .await;

    match existing {
        Err(e) => return HttpResponse::InternalServerError().body(format!("Error: {}", e)),
        Ok(Some(row)) => {
            // Ya existe: solo aseguramos que tenga rol residente
            if let Err(e) = asegurar_rol_residente(pool.get_ref(), row.id_persona).await {
                return db_err_to_http(e, "Error asegurando rol residente");
            }

            // Cargamos roles (igual que en /login)
            let roles_rows = sqlx::query_as::<_, RolRow>(
                r#"
                SELECT r.nombre
                FROM persona_rol pr
                JOIN rol r ON pr.id_rol=r.id_rol
                WHERE pr.id_persona=$1
                "#,
            )
            .bind(row.id_persona)
            .fetch_all(pool.get_ref())
            .await;

            let roles = match roles_rows {
                Ok(list) => list.into_iter().map(|r| r.nombre).collect::<Vec<String>>(),
                Err(e) => return HttpResponse::InternalServerError().body(format!("Error roles: {}", e)),
            };

            let nombre_completo = match row.segundo_apellido {
                Some(seg) => format!("{} {} {}", row.nombre, row.primer_apellido, seg),
                None => format!("{} {}", row.nombre, row.primer_apellido),
            };

            return HttpResponse::Ok().json(LoginResponse {
                id_usuario: row.id_usuario,
                id_persona: row.id_persona,
                correo: row.correo_login,
                nombre_completo,
                roles,
            });
        }
        Ok(None) => {
            // No existe: lo creamos como persona + usuario + rol residente
        }
    }

    // 2) Crear persona + usuario + rol residente
    let mut tx = match pool.begin().await {
        Ok(t) => t,
        Err(e) => return HttpResponse::InternalServerError().body(format!("TX error: {e}")),
    };

    // Persona
    let id_persona_res: Result<i32, sqlx::Error> = sqlx::query_scalar(
        r#"
        INSERT INTO persona (
          nombre,
          primer_apellido,
          segundo_apellido,
          correo,
          telefono,
          no_residencia
        )
        VALUES ($1,$2,$3,$4,NULL,NULL)
        RETURNING id_persona
        "#,
    )
    .bind(&nombre)
    .bind(&primer_apellido)
    .bind(&segundo_apellido)
    .bind(&correo)
    .fetch_one(&mut *tx)
    .await;

    let id_persona = match id_persona_res {
        Ok(id) => id,
        Err(e) => {
            let _ = tx.rollback().await;
            return db_err_to_http(e, "Error insert persona (google)");
        }
    };

    // Usuario (contraseña dummy, no se usa realmente)
    let contrasena_dummy = "google_oauth";
    let id_usuario_res: Result<i32, sqlx::Error> = sqlx::query_scalar(
        r#"
        INSERT INTO usuario (id_persona, correo_login, contrasena, activo)
        VALUES ($1, $2, $3, TRUE)
        RETURNING id_usuario
        "#,
    )
    .bind(id_persona)
    .bind(&correo)
    .bind(contrasena_dummy)
    .fetch_one(&mut *tx)
    .await;

    let id_usuario = match id_usuario_res {
        Ok(id) => id,
        Err(e) => {
            let _ = tx.rollback().await;
            return db_err_to_http(e, "Error insert usuario (google)");
        }
    };

    // Rol residente
    let res_rol = sqlx::query(
        r#"
        INSERT INTO persona_rol (id_persona, id_rol, fecha_inicio)
        SELECT $1, id_rol, CURRENT_DATE
        FROM rol
        WHERE nombre = 'residente'
        ON CONFLICT (id_persona, id_rol) DO NOTHING
        "#,
    )
    .bind(id_persona)
    .execute(&mut *tx)
    .await;

    if let Err(e) = res_rol {
        let _ = tx.rollback().await;
        return db_err_to_http(e, "Error insert rol residente (google)");
    }

    if let Err(e) = tx.commit().await {
        return HttpResponse::InternalServerError().body(format!("Commit error: {e}"));
    }

    // 3) Obtener roles (ya debe tener al menos 'residente')
    let roles_rows = sqlx::query_as::<_, RolRow>(
        r#"
        SELECT r.nombre
        FROM persona_rol pr
        JOIN rol r ON pr.id_rol=r.id_rol
        WHERE pr.id_persona=$1
        "#,
    )
    .bind(id_persona)
    .fetch_all(pool.get_ref())
    .await;

    let roles = match roles_rows {
        Ok(list) => list.into_iter().map(|r| r.nombre).collect::<Vec<String>>(),
        Err(e) => return HttpResponse::InternalServerError().body(format!("Error roles: {}", e)),
    };

    let nombre_completo = if let Some(seg) = segundo_apellido {
        format!("{} {} {}", nombre, primer_apellido, seg)
    } else {
        format!("{} {}", nombre, primer_apellido)
    };

    HttpResponse::Ok().json(LoginResponse {
        id_usuario,
        id_persona,
        correo,
        nombre_completo,
        roles,
    })
}


async fn login(pool: web::Data<PgPool>, creds: web::Json<LoginRequest>) -> impl Responder {
    let usuario_row = sqlx::query_as::<_, LoginRow>(
        r#"
        SELECT u.id_usuario, u.id_persona, u.correo_login, u.contrasena,
               p.nombre, p.primer_apellido, p.segundo_apellido
        FROM usuario u
        JOIN persona p ON u.id_persona=p.id_persona
        WHERE u.correo_login=$1
        "#,
    )
    .bind(&creds.correo)
    .fetch_optional(pool.get_ref())
    .await;

    let usuario_row = match usuario_row {
        Ok(Some(row)) => row,
        Ok(None) => return HttpResponse::Unauthorized().body("Usuario no encontrado"),
        Err(e) => return HttpResponse::InternalServerError().body(format!("Error: {}", e)),
    };

    if usuario_row.contrasena != creds.contrasena {
        return HttpResponse::Unauthorized().body("Contraseña incorrecta");
    }

    let roles_rows = sqlx::query_as::<_, RolRow>(
        r#"
        SELECT r.nombre
        FROM persona_rol pr
        JOIN rol r ON pr.id_rol=r.id_rol
        WHERE pr.id_persona=$1
        "#,
    )
    .bind(usuario_row.id_persona)
    .fetch_all(pool.get_ref())
    .await;

    let roles = match roles_rows {
        Ok(list) => list.into_iter().map(|r| r.nombre).collect::<Vec<String>>(),
        Err(e) => return HttpResponse::InternalServerError().body(format!("Error roles: {}", e)),
    };

    let nombre_completo = match usuario_row.segundo_apellido {
        Some(seg) => format!("{} {} {}", usuario_row.nombre, usuario_row.primer_apellido, seg),
        None => format!("{} {}", usuario_row.nombre, usuario_row.primer_apellido),
    };

    HttpResponse::Ok().json(LoginResponse {
        id_usuario: usuario_row.id_usuario,
        id_persona: usuario_row.id_persona,
        correo: usuario_row.correo_login,
        nombre_completo,
        roles,
    })
}

// =====================================
// REGISTRAR DISPOSITIVO (push_token)
// =====================================

async fn registrar_dispositivo(pool: web::Data<PgPool>, body: web::Json<DispositivoInput>) -> impl Responder {
    let res = sqlx::query(
        r#"
        INSERT INTO dispositivo (id_persona, plataforma, push_token, activo)
        VALUES ($1, $2, $3, TRUE)
        ON CONFLICT (id_persona, push_token)
        DO UPDATE SET activo=TRUE, plataforma=EXCLUDED.plataforma
        "#,
    )
    .bind(body.id_persona)
    .bind(&body.plataforma)
    .bind(&body.push_token)
    .execute(pool.get_ref())
    .await;

    match res {
        Ok(_) => HttpResponse::Ok().body("Dispositivo registrado"),
        Err(e) => HttpResponse::InternalServerError().body(format!("Error: {e}")),
    }
}

// =====================================
// VALIDAR SI EMISOR PUEDE AVISAR
// =====================================

async fn emisor_puede_enviar(pool: &PgPool, id_usuario: i32) -> Result<bool, sqlx::Error> {
    #[derive(FromRow)]
    struct UserPersonaRow {
        id_persona: i32,
    }

    let row = sqlx::query_as::<_, UserPersonaRow>("SELECT id_persona FROM usuario WHERE id_usuario=$1")
        .bind(id_usuario)
        .fetch_one(pool)
        .await?;

    let roles = sqlx::query_as::<_, RolRow>(
        r#"
        SELECT r.nombre
        FROM persona_rol pr
        JOIN rol r ON pr.id_rol=r.id_rol
        WHERE pr.id_persona=$1
        "#,
    )
    .bind(row.id_persona)
    .fetch_all(pool)
    .await?;

    let list = roles.into_iter().map(|r| r.nombre).collect::<Vec<_>>();
    Ok(list.contains(&"admin".to_string()) || list.contains(&"mesa_directiva".to_string()))
}

// =====================================
// FCM ACCESS TOKEN
// =====================================

async fn get_fcm_access_token() -> Result<String, Box<dyn std::error::Error>> {
    // lee el service account de fcm_service_account.json
    let key = read_service_account_key("fcm_service_account.json").await?;
    let auth = ServiceAccountAuthenticator::builder(key).build().await?;

    // pide token para el scope de FCM
    let access = auth
        .token(&["https://www.googleapis.com/auth/firebase.messaging"])
        .await?;

    // AccessToken -> usamos .token(), no .as_str()
    let token_str = access
        .token()                        // Option<&str>
        .ok_or("Token FCM vacío")?      // si viene None, error
        .to_string();                   // &str -> String

    Ok(token_str)
}

// =====================================
// ENVIAR PUSH FCM
// =====================================

async fn send_fcm_push(
    pool: &PgPool,
    titulo: &str,
    mensaje: &str,
    destinatarios: &Vec<i32>,
) -> Result<(), Box<dyn std::error::Error>> {
    if destinatarios.is_empty() {
        println!("ℹ️ send_fcm_push: sin destinatarios -> no envío nada");
        return Ok(());
    }

    let tokens_rows = sqlx::query_as::<_, PushTokenRow>(
        r#"
        SELECT push_token
        FROM dispositivo
        WHERE activo = TRUE AND id_persona = ANY($1)
        "#,
    )
    .bind(destinatarios)
    .fetch_all(pool)
    .await?;

    let tokens: Vec<String> = tokens_rows.into_iter().map(|r| r.push_token).collect();

    if tokens.is_empty() {
        println!("ℹ️ send_fcm_push: no hay tokens activos para {:?}", destinatarios);
        return Ok(());
    }

    let bearer = get_fcm_access_token().await?;
    let project_id = env::var("FCM_PROJECT_ID")?; // ej. fraccionamiento-app
    let url = format!(
        "https://fcm.googleapis.com/v1/projects/{}/messages:send",
        project_id
    );

    let client = HttpClient::new();

    for t in tokens {
        let body = serde_json::json!({
          "message": {
            "token": t,
            "notification": { "title": titulo, "body": mensaje },
            "android": {
              "priority": "HIGH",
              "notification": { "channel_id": "avisos", "sound": "default" }
            },
            "data": {
              "tipo": "aviso",
              "click_action": "FLUTTER_NOTIFICATION_CLICK"
            }
          }
        });

        let res = client
            .post(&url)
            .bearer_auth(&bearer)
            .json(&body)
            .send()
            .await?;

        let status = res.status();
        let txt = res.text().await.unwrap_or_default();

        if status.is_success() {
            println!("✅ FCM enviado OK -> {status} {txt}");
        } else {
            println!("❌ FCM error -> {status} {txt}");
        }
    }

    Ok(())
}

// =====================================
// AVISOS
// =====================================

async fn crear_aviso(pool: web::Data<PgPool>, body: web::Json<AvisoInput>) -> impl Responder {
    match emisor_puede_enviar(pool.get_ref(), body.id_usuario_emisor).await {
        Ok(true) => {}
        Ok(false) => return HttpResponse::Forbidden().body("No tienes permiso"),
        Err(e) => return HttpResponse::InternalServerError().body(e.to_string()),
    };

    let id_aviso_res = sqlx::query_scalar::<_, i32>(
        r#"
        INSERT INTO aviso (titulo, mensaje, a_todos, enviado_por)
        VALUES ($1,$2,$3,$4)
        RETURNING id_aviso
        "#,
    )
    .bind(&body.titulo)
    .bind(&body.mensaje)
    .bind(body.a_todos)
    .bind(body.id_usuario_emisor)
    .fetch_one(pool.get_ref())
    .await;

    let id_aviso = match id_aviso_res {
        Ok(v) => v,
        Err(e) => return HttpResponse::InternalServerError().body(e.to_string()),
    };

    if !body.a_todos {
        let destinatarios = body.destinatarios.clone().unwrap_or_default();
        for id_persona in &destinatarios {
            let _ = sqlx::query(
                r#"
                INSERT INTO aviso_destinatario (id_aviso, id_persona)
                VALUES ($1,$2)
                "#,
            )
            .bind(id_aviso)
            .bind(*id_persona)
            .execute(pool.get_ref())
            .await;
        }
    }

    let recipients: Vec<i32> = if body.a_todos {
        #[derive(FromRow)]
        struct PersonaIdRow {
            id_persona: i32,
        }

        sqlx::query_as::<_, PersonaIdRow>("SELECT id_persona FROM persona")
            .fetch_all(pool.get_ref())
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|r| r.id_persona)
            .collect()
    } else {
        body.destinatarios.clone().unwrap_or_default()
    };

    let _ = send_fcm_push(pool.get_ref(), &body.titulo, &body.mensaje, &recipients).await;

    HttpResponse::Ok().json(serde_json::json!({ "ok": true, "id_aviso": id_aviso }))
}

async fn obtener_avisos(pool: web::Data<PgPool>) -> impl Responder {
    let result = sqlx::query_as::<_, AvisoRow>(
        r#"
        SELECT a.id_aviso, a.titulo, a.mensaje, a.a_todos,
               a.enviado_por, a.creado_en,
               (p.nombre || ' ' || p.primer_apellido) AS nombre_emisor
        FROM aviso a
        JOIN usuario u ON a.enviado_por=u.id_usuario
        JOIN persona p ON u.id_persona=p.id_persona
        ORDER BY a.creado_en DESC
        "#,
    )
    .fetch_all(pool.get_ref())
    .await;

    match result {
        Ok(list) => HttpResponse::Ok().json(list),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

async fn obtener_avisos_persona(pool: web::Data<PgPool>, path: web::Path<i32>) -> impl Responder {
    let id_persona = path.into_inner();

    let result = sqlx::query_as::<_, AvisoRow>(
        r#"
        SELECT a.id_aviso, a.titulo, a.mensaje, a.a_todos,
               a.enviado_por, a.creado_en,
               (p.nombre || ' ' || p.primer_apellido) AS nombre_emisor
        FROM aviso a
        JOIN usuario u ON a.enviado_por=u.id_usuario
        JOIN persona p ON u.id_persona=p.id_persona
        LEFT JOIN aviso_destinatario d ON a.id_aviso=d.id_aviso
        WHERE a.a_todos=TRUE OR d.id_persona=$1
        ORDER BY a.creado_en DESC
        "#,
    )
    .bind(id_persona)
    .fetch_all(pool.get_ref())
    .await;

    match result {
        Ok(list) => HttpResponse::Ok().json(list),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

async fn contar_no_leidos(pool: web::Data<PgPool>, path: web::Path<i32>) -> impl Responder {
    let id_persona = path.into_inner();

    #[derive(FromRow)]
    struct CountRow {
        total: i64,
    }

    let row = sqlx::query_as::<_, CountRow>(
        r#"
        SELECT COUNT(*)::BIGINT AS total
        FROM aviso a
        LEFT JOIN aviso_destinatario d ON a.id_aviso=d.id_aviso
        LEFT JOIN aviso_lectura l
            ON l.id_aviso=a.id_aviso AND l.id_persona=$1
        WHERE l.id_aviso IS NULL
          AND (a.a_todos=TRUE OR d.id_persona=$1)
        "#,
    )
    .bind(id_persona)
    .fetch_one(pool.get_ref())
    .await;

    match row {
        Ok(r) => HttpResponse::Ok().json(serde_json::json!({ "unread": r.total })),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

async fn marcar_leidos(pool: web::Data<PgPool>, body: web::Json<LeerAvisosInput>) -> impl Responder {
    for id_aviso in &body.ids_avisos {
        let _ = sqlx::query(
            r#"
            INSERT INTO aviso_lectura (id_aviso, id_persona)
            VALUES ($1,$2)
            ON CONFLICT DO NOTHING
            "#,
        )
        .bind(*id_aviso)
        .bind(body.id_persona)
        .execute(pool.get_ref())
        .await;
    }

    HttpResponse::Ok().body("OK")
}

// =====================================
// PAGOS
// =====================================

async fn obtener_pagos_pendientes(pool: web::Data<PgPool>, path: web::Path<i32>) -> impl Responder {
    let id_persona = path.into_inner();

    let res = sqlx::query_as::<_, PagoRow>(
        r#"
        SELECT
            no_transaccion,
            fecha_transaccion,
            id_persona,
            id_usuario_registro,
            id_tipo_cuota,
            cve_tipo_pago,
            total::text as total,
            estado
        FROM pagos
        WHERE id_persona = $1
          AND lower(estado) = 'pendiente'
        ORDER BY fecha_transaccion DESC
        "#,
    )
    .bind(id_persona)
    .fetch_all(pool.get_ref())
    .await;

    match res {
        Ok(list) => HttpResponse::Ok().json(list),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

async fn obtener_pagos_historial(pool: web::Data<PgPool>, path: web::Path<i32>) -> impl Responder {
    let id_persona = path.into_inner();

    let res = sqlx::query_as::<_, PagoRow>(
        r#"
        SELECT
            no_transaccion,
            fecha_transaccion,
            id_persona,
            id_usuario_registro,
            id_tipo_cuota,
            cve_tipo_pago,
            total::text as total,
            estado
        FROM pagos
        WHERE id_persona = $1
          AND lower(estado) <> 'pendiente'
        ORDER BY fecha_transaccion DESC
        "#,
    )
    .bind(id_persona)
    .fetch_all(pool.get_ref())
    .await;

    match res {
        Ok(list) => HttpResponse::Ok().json(list),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

// POST /pagos/crear_intent
async fn crear_intent_stripe(pool: web::Data<PgPool>, body: web::Json<CrearIntentReq>) -> impl Responder {
    let _ = pool;

    let secret_key = match env::var("STRIPE_SECRET_KEY") {
        Ok(v) => v,
        Err(_) => return HttpResponse::InternalServerError().body("Falta STRIPE_SECRET_KEY"),
    };

    let client = StripeClient::new(secret_key);

    let currency = match body.moneda.to_lowercase().as_str() {
        "mxn" => Currency::MXN,
        "usd" => Currency::USD,
        _ => Currency::MXN,
    };

    let mut params = CreatePaymentIntent::new(body.monto_centavos, currency);

    params.automatic_payment_methods = Some(CreatePaymentIntentAutomaticPaymentMethods {
        enabled: true,
        ..Default::default()
    });

    params.metadata = Some(HashMap::from([
        ("no_transaccion".to_string(), body.no_transaccion.to_string()),
        ("id_persona".to_string(), body.id_persona.to_string()),
        ("id_usuario_registro".to_string(), body.id_usuario.to_string()),
        ("id_tipo_cuota".to_string(), body.id_tipo_cuota.to_string()),
        ("cve_tipo_pago".to_string(), body.cve_tipo_pago.to_string()),
        ("descripcion".to_string(), body.descripcion.clone()),
        ("monto_centavos".to_string(), body.monto_centavos.to_string()),
    ]));

    match PaymentIntent::create(&client, params).await {
        Ok(pi) => {
            let client_secret = match pi.client_secret {
                Some(cs) => cs,
                None => {
                    return HttpResponse::BadRequest().json(serde_json::json!({
                        "error": "Stripe no devolvió client_secret"
                    }))
                }
            };

            HttpResponse::Ok().json(serde_json::json!({
                "client_secret": client_secret,
                "payment_intent_id": pi.id.to_string()
            }))
        }
        Err(e) => {
            eprintln!("Stripe error: {e:?}");
            HttpResponse::BadRequest().json(serde_json::json!({
                "error": "No se pudo crear PaymentIntent"
            }))
        }
    }
}

// (OPCIONAL) WEBHOOK Stripe
async fn stripe_webhook(req: HttpRequest, payload: Bytes, pool: web::Data<PgPool>) -> impl Responder {
    let webhook_secret = match env::var("STRIPE_WEBHOOK_SECRET") {
        Ok(v) => v,
        Err(_) => return HttpResponse::InternalServerError().body("Falta STRIPE_WEBHOOK_SECRET"),
    };

    let sig_header = req
        .headers()
        .get("Stripe-Signature")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let event = match Webhook::construct_event(
        std::str::from_utf8(&payload).unwrap_or(""),
        sig_header,
        webhook_secret.as_str(),
    ) {
        Ok(ev) => ev,
        Err(e) => {
            eprintln!("❌ Webhook signature error: {e:?}");
            return HttpResponse::BadRequest().body("Invalid signature");
        }
    };

    match event.type_ {
        EventType::PaymentIntentSucceeded => {
            if let EventObject::PaymentIntent(pi) = event.data.object {
                let md = pi.metadata;
                let no_transaccion = md.get("no_transaccion").and_then(|v| v.parse::<i32>().ok());
                let id_persona = md.get("id_persona").and_then(|v| v.parse::<i32>().ok());

                if let (Some(no_transaccion), Some(id_persona)) = (no_transaccion, id_persona) {
                    let _ = sqlx::query(
                        r#"
                        UPDATE pagos
                        SET estado='pagado'
                        WHERE no_transaccion=$1 AND id_persona=$2
                        "#,
                    )
                    .bind(no_transaccion)
                    .bind(id_persona)
                    .execute(pool.get_ref())
                    .await;
                }
            }
        }
        EventType::PaymentIntentPaymentFailed => {
            if let EventObject::PaymentIntent(pi) = event.data.object {
                let md = pi.metadata;
                let no_transaccion = md.get("no_transaccion").and_then(|v| v.parse::<i32>().ok());
                let id_persona = md.get("id_persona").and_then(|v| v.parse::<i32>().ok());

                if let (Some(no_transaccion), Some(id_persona)) = (no_transaccion, id_persona) {
                    let _ = sqlx::query(
                        r#"
                        UPDATE pagos
                        SET estado='fallido'
                        WHERE no_transaccion=$1 AND id_persona=$2
                        "#,
                    )
                    .bind(no_transaccion)
                    .bind(id_persona)
                    .execute(pool.get_ref())
                    .await;
                }
            }
        }
        _ => {}
    }

    HttpResponse::Ok().body("ok")
}

// Endpoint para confirmar (desde Flutter) y registrar en BD
async fn confirmar_pago(
    pool: web::Data<PgPool>,
    body: web::Json<ConfirmarPagoReq>,
) -> impl Responder {
    let secret_key = match env::var("STRIPE_SECRET_KEY") {
        Ok(v) => v,
        Err(_) => return HttpResponse::InternalServerError().body("Falta STRIPE_SECRET_KEY"),
    };

    let client = StripeClient::new(secret_key);

    let pi_id: PaymentIntentId = match body.payment_intent_id.parse() {
        Ok(id) => id,
        Err(_) => return HttpResponse::BadRequest().body("payment_intent_id inválido"),
    };

    let pi = match PaymentIntent::retrieve(&client, &pi_id, &[]).await {
        Ok(pi) => pi,
        Err(e) => {
            eprintln!("Stripe retrieve error: {e:?}");
            return HttpResponse::BadRequest().body("No se pudo recuperar PaymentIntent");
        }
    };

    if pi.status != PaymentIntentStatus::Succeeded {
        return HttpResponse::BadRequest()
            .body(format!("Pago no aprobado. status={:?}", pi.status));
    }

    let meta: HashMap<String, String> = pi.metadata.clone();

    let no_transaccion = match get_meta_i32(&meta, "no_transaccion") {
        Ok(v) => v,
        Err(e) => return HttpResponse::BadRequest().body(e),
    };

    let id_persona = match get_meta_i32(&meta, "id_persona") {
        Ok(v) => v,
        Err(e) => return HttpResponse::BadRequest().body(e),
    };

    let id_usuario_registro = match get_meta_i32(&meta, "id_usuario_registro") {
        Ok(v) => v,
        Err(e) => return HttpResponse::BadRequest().body(e),
    };

    let id_tipo_cuota = match get_meta_i32(&meta, "id_tipo_cuota") {
        Ok(v) => v,
        Err(e) => return HttpResponse::BadRequest().body(e),
    };

    let cve_tipo_pago = match get_meta_i32(&meta, "cve_tipo_pago") {
        Ok(v) => v,
        Err(e) => return HttpResponse::BadRequest().body(e),
    };

    let descripcion = meta
        .get("descripcion")
        .cloned()
        .unwrap_or_else(|| "Pago".to_string());

    let amount_centavos: i64 = pi.amount;
    let meta_centavos = get_meta_i64(&meta, "monto_centavos").unwrap_or(amount_centavos);

    if meta_centavos != amount_centavos {
        return HttpResponse::BadRequest().body("Monto no coincide con metadata");
    }

    let total_str = centavos_a_str_2dec(amount_centavos);

    let mut tx = match pool.begin().await {
        Ok(t) => t,
        Err(e) => return HttpResponse::InternalServerError().body(format!("TX error: {e}")),
    };

    let ya: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::BIGINT FROM pagos WHERE stripe_payment_intent_id = $1",
    )
    .bind(pi.id.to_string())
    .fetch_one(&mut *tx)
    .await
    .unwrap_or(0);

    if ya > 0 {
        let _ = tx.commit().await;
        return HttpResponse::Ok().body("Ya registrado");
    }

    let existe_persona: i64 = sqlx::query_scalar("SELECT COUNT(*)::BIGINT FROM persona WHERE id_persona=$1")
        .bind(id_persona)
        .fetch_one(&mut *tx)
        .await
        .unwrap_or(0);

    if existe_persona == 0 {
        let _ = tx.rollback().await;
        return HttpResponse::BadRequest().body(format!("id_persona no existe: {}", id_persona));
    }

    if let Err(e) = sqlx::query(
        r#"
        INSERT INTO pagos (
          no_transaccion, id_persona, id_usuario_registro, id_tipo_cuota, cve_tipo_pago,
          total, estado, stripe_payment_intent_id
        )
        VALUES ($1,$2,$3,$4,$5, ($6)::numeric, 'pagado', $7)
        ON CONFLICT (no_transaccion)
        DO UPDATE SET
          id_persona = EXCLUDED.id_persona,
          id_usuario_registro = EXCLUDED.id_usuario_registro,
          id_tipo_cuota = EXCLUDED.id_tipo_cuota,
          cve_tipo_pago = EXCLUDED.cve_tipo_pago,
          total = EXCLUDED.total,
          estado = 'pagado',
          stripe_payment_intent_id = EXCLUDED.stripe_payment_intent_id,
          fecha_transaccion = NOW()
        "#,
    )
    .bind(no_transaccion)
    .bind(id_persona)
    .bind(id_usuario_registro)
    .bind(id_tipo_cuota)
    .bind(cve_tipo_pago)
    .bind(&total_str)
    .bind(pi.id.to_string())
    .execute(&mut *tx)
    .await
    {
        let _ = tx.rollback().await;
        return HttpResponse::InternalServerError().body(format!("Insert pagos error: {e}"));
    }

    let _ = sqlx::query("DELETE FROM pago_detalle WHERE no_transaccion = $1")
        .bind(no_transaccion)
        .execute(&mut *tx)
        .await;

    if let Err(e) = sqlx::query(
        r#"
        INSERT INTO pago_detalle (no_transaccion, descripcion, monto)
        VALUES ($1,$2, ($3)::numeric)
        "#,
    )
    .bind(no_transaccion)
    .bind(&descripcion)
    .bind(&total_str)
    .execute(&mut *tx)
    .await
    {
        let _ = tx.rollback().await;
        return HttpResponse::InternalServerError().body(format!("Insert pago_detalle error: {e}"));
    }

    if let Err(e) = tx.commit().await {
        return HttpResponse::InternalServerError().body(format!("Commit error: {e}"));
    }

    HttpResponse::Ok().json(serde_json::json!({
        "ok": true,
        "no_transaccion": no_transaccion,
        "stripe_payment_intent_id": pi.id.to_string()
    }))
}

fn month_range(yyyy_mm: &str) -> Result<(NaiveDate, NaiveDate), String> {
    let parts: Vec<&str> = yyyy_mm.split('-').collect();
    if parts.len() != 2 {
        return Err("month debe ser YYYY-MM".to_string());
    }
    let y: i32 = parts[0].parse().map_err(|_| "Año inválido".to_string())?;
    let m: u32 = parts[1].parse().map_err(|_| "Mes inválido".to_string())?;
    if m < 1 || m > 12 {
        return Err("Mes debe ser 01..12".to_string());
    }

    let start = NaiveDate::from_ymd_opt(y, m, 1).ok_or("Fecha inválida".to_string())?;
    let (ny, nm) = if m == 12 { (y + 1, 1) } else { (y, m + 1) };
    let end = NaiveDate::from_ymd_opt(ny, nm, 1).ok_or("Fecha inválida".to_string())?;
    Ok((start, end))
}

// GET /areas/{cve_area}/fechas_ocupadas?month=YYYY-MM
async fn fechas_ocupadas_area(
    pool: web::Data<PgPool>,
    path: web::Path<i32>,
    q: web::Query<FechasOcupadasQuery>,
) -> impl Responder {
    let cve_area = path.into_inner();

    // por defecto: mes actual
    let month = q.month.clone().unwrap_or_else(|| {
        let now = chrono::Local::now().date_naive();
        format!("{:04}-{:02}", now.year(), now.month())
    });

    let (start, end) = match month_range(&month) {
        Ok(r) => r,
        Err(msg) => return HttpResponse::BadRequest().body(msg),
    };

    // Nota: aquí "ocupada" = existe al menos una reserva ese día (pendiente/confirmada)
    let fechas = sqlx::query_scalar::<_, NaiveDate>(
        r#"
        SELECT DISTINCT fecha_reserva
        FROM reservas
        WHERE cve_area = $1
          AND fecha_reserva >= $2
          AND fecha_reserva <  $3
          AND lower(estado) IN ('pendiente','confirmada')
        ORDER BY fecha_reserva
        "#,
    )
    .bind(cve_area)
    .bind(start)
    .bind(end)
    .fetch_all(pool.get_ref())
    .await;

    match fechas {
        Ok(list) => {
            let out: Vec<String> = list.into_iter().map(|d| d.format("%Y-%m-%d").to_string()).collect();
            HttpResponse::Ok().json(serde_json::json!({ "fechas": out }))
        }
        Err(e) => HttpResponse::InternalServerError().body(format!("DB error: {e}")),
    }
}

// =====================================
// TRANSACCIONES (STUBS)
// =====================================

async fn simular_transaccion() -> impl Responder {
    HttpResponse::NotImplemented().body("Endpoint /transaccion/simular aún no está implementado")
}

async fn ejecutar_transaccion() -> impl Responder {
    HttpResponse::NotImplemented().body("Endpoint /transaccion/ejecutar aún no está implementado")
}

// =====================================
// MAIN
// =====================================

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();

    let port: u16 = env::var("PORT")
        .unwrap_or_else(|_| "3002".to_string())
        .parse()
        .expect("PORT inválido");

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL no está en el .env");

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("No se pudo conectar a la base de datos");

    println!("🚀 Servidor escuchando en http://0.0.0.0:{port}");

    HttpServer::new(move || {
        App::new()
            .wrap(
                Cors::default()
                    .allow_any_origin()
                    .allow_any_method()
                    .allow_any_header(),
            )
            .app_data(web::Data::new(pool.clone()))
            // PERSONAS
            .route("/personas", web::get().to(obtener_personas))
            .route("/persona", web::post().to(crear_persona))
            .route("/persona/{id}", web::put().to(actualizar_persona))
            .route("/persona/{id}", web::delete().to(eliminar_persona))
            // LOGIN
            //.route("/login", web::post().to(login))
            // LOGIN
            .route("/login", web::post().to(login))
            .route("/login/google", web::post().to(login_google))

            // AVISOS + PUSH
            .route("/avisos", web::get().to(obtener_avisos))
            .route("/avisos", web::post().to(crear_aviso))
            .route("/avisos/persona/{id_persona}", web::get().to(obtener_avisos_persona))
            .route("/avisos/unread/{id_persona}", web::get().to(contar_no_leidos))
            .route("/avisos/leer", web::post().to(marcar_leidos))
            // DISPOSITIVOS
            .route("/dispositivo", web::post().to(registrar_dispositivo))
            // TRANSACCION
            .route("/transaccion/simular", web::post().to(simular_transaccion))
            .route("/transaccion/ejecutar", web::post().to(ejecutar_transaccion))
            // PAGOS
            .route("/pagos/pendientes/{id_persona}", web::get().to(obtener_pagos_pendientes))
            .route("/pagos/historial/{id_persona}", web::get().to(obtener_pagos_historial))
            .route("/pagos/crear_intent", web::post().to(crear_intent_stripe))
            .route("/pagos/confirmar", web::post().to(confirmar_pago))
            // STRIPE (opcional)
            .route("/stripe/webhook", web::post().to(stripe_webhook))
            // AREA COMÚN + RESERVAS
            .route("/areas", web::get().to(obtener_areas))
            .route("/areas/{cve_area}/disponibilidad", web::get().to(disponibilidad_area))
            .route("/reservas", web::post().to(crear_reserva))
            .route("/reservas/persona/{id_persona}", web::get().to(reservas_por_persona))
            .route("/areas/{cve_area}/fechas_ocupadas", web::get().to(fechas_ocupadas_area))
    })
    .bind(("0.0.0.0", port))?
    .run()
    .await
}


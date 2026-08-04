# Configuración de Telegram para SIEM

## Paso 1: Crear Bot en Telegram

1. Abrir Telegram y buscar `@BotFather`
2. Enviar el comando `/newbot`
3. Elegir un nombre para el bot: `SIEM Alertas`
4. Elegir un username: `siem_alertas_bot` (debe terminar en `bot`)
5. **Guardar el TOKEN** que te da BotFather (ejemplo: `7123456789:AAH...`)

## Paso 2: Obtener tu Chat ID

1. Buscar tu bot en Telegram y enviarle un mensaje cualquiera
2. Abrir en navegador: `https://api.telegram.org/bot<TU_TOKEN>/getUpdates`
3. Buscar el campo `"chat":{"id":123456789}` - ese es tu Chat ID

## Paso 3: Configurar en n8n

1. Abrir http://localhost:5678
2. Ir a **Credenciales** (Credentials)
3. Crear nueva credencial tipo **Telegram API**:
   - Name: `Telegram Bot SIEM`
   - Access Token: `<TU_TOKEN_DE_BOTFATHER>`
4. Guardar

## Paso 4: Importar Workflow

1. Ir a **Workflows** → **Import from file**
2. Seleccionar `n8n/SIEM - Alerta Entrante.json`
3. Editar el nodo **Notificar Telegram**:
   - Credential: seleccionar `Telegram Bot SIEM`
   - Chat ID: poner tu Chat ID (ej: `123456789`)
4. **Activar** el workflow (toggle arriba a la derecha)

## Paso 5: Probar

Enviar alerta de prueba:

```powershell
$headers = @{
    "x-siem-key" = "superpoderosas26"
    "Content-Type" = "application/json"
}
$body = @{
    rule_id = "test_telegram"
    src_ip = "192.168.1.100"
    username = "test_user"
    severity = "high"
    timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
} | ConvertTo-Json

Invoke-RestMethod -Uri "http://localhost:5678/webhook/alert/siem" -Method POST -Headers $headers -Body $body
```

¡Deberías recibir la notificación en Telegram! 🎉
